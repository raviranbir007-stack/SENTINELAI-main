"""
Terminal Activity Monitor Display
Shows real-time activity monitoring summaries on server terminal
"""

import logging
import os
import shutil
import sys
import threading
import textwrap
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
    
    def __init__(self, update_interval: int = 3600):
        self.update_interval = update_interval  # Seconds between updates
        self.running = False
        self.monitor_thread = None
        
        # Activity counters
        self.activity_buffer: Deque[Dict] = deque(maxlen=5000)
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
        self._last_status_latest = ""

    def _record_activity(self, activity_type: str, **payload):
        """Store recent activity for rolling coverage summaries."""
        self.activity_buffer.append({
            'type': str(activity_type or 'activity'),
            'time': datetime.now(timezone.utc),
            **payload,
        })

    def _coverage_events(self, now: datetime) -> list[Dict]:
        """Return events seen within the current coverage window."""
        cutoff = now - timedelta(seconds=self.update_interval)
        return [event for event in self.activity_buffer if event.get('time') and event['time'] >= cutoff]

    def _format_relative_time(self, now: datetime, event_time: datetime | None) -> str:
        """Format a short relative time label."""
        if not event_time:
            return "No activity in window"

        delta = max(0, int((now - event_time).total_seconds()))
        if delta < 60:
            return f"{delta}s ago"
        if delta < 3600:
            return f"{int(delta / 60)}m ago"
        return f"{int(delta / 3600)}h ago"

    def _latest_coverage_label(self, events: list[Dict]) -> str:
        """Build the latest activity label from the current coverage window."""
        if not events:
            return "No new target in coverage window"

        latest_event = events[-1]
        event_type = str(latest_event.get('type') or '').lower()

        if event_type == 'attack':
            return str(latest_event.get('attack_type') or 'Unknown attack').replace('_', ' ').title()
        if event_type == 'threat':
            return str(latest_event.get('artifact_type') or 'Threat').upper()
        if event_type == 'website':
            return self._compact_target(str(latest_event.get('domain') or 'activity'))
        if event_type == 'app':
            return str(latest_event.get('app_name') or 'Application activity')
        if event_type == 'scan':
            return f"Scan · {str(latest_event.get('artifact_type') or 'artifact').upper()}"
        if event_type == 'connection':
            return 'Network connection activity'

        return 'Recent monitored activity'
        
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
        self._record_activity('website', domain=domain, risk_level=risk_level)
        
        activity = f"{domain} [{risk_level}]"
        if activity not in self.recent_websites:
            self.recent_websites.append(activity)
    
    def log_app_activity(self, app_name: str, risk_level: str = 'LOW'):
        """Log application activity"""
        self.stats['apps_monitored'] += 1
        self.stats['last_activity_time'] = datetime.now(timezone.utc)
        self._record_activity('app', app_name=app_name, risk_level=risk_level)
        
        activity = f"{app_name} [{risk_level}]"
        if activity not in self.recent_apps:
            self.recent_apps.append(activity)
    
    def log_connection_activity(self):
        """Log network connection"""
        self.stats['connections_monitored'] += 1
        self.stats['last_activity_time'] = datetime.now(timezone.utc)
        self._record_activity('connection')
    
    def log_scan_activity(self, artifact_type: str, artifact_value: str, verdict: str):
        """Log threat scan activity"""
        self.stats['scans_performed'] += 1
        self.stats['last_activity_time'] = datetime.now(timezone.utc)

        normalized_type = str(artifact_type or '').lower()
        normalized_verdict = str(verdict or '').lower()
        self._record_activity(
            'scan',
            artifact_type=artifact_type,
            artifact_value=artifact_value,
            verdict=normalized_verdict,
        )

        # Suppress noisy single-signal IP suspicious events from terminal threat ticker.
        # These are already handled by deeper corroboration paths.
        if normalized_type == 'ip' and normalized_verdict == 'suspicious':
            return
        
        if normalized_verdict in ['malicious', 'suspicious', 'critical']:
            self.stats['threats_detected'] += 1
            self._record_activity(
                'threat',
                artifact_type=artifact_type,
                artifact_value=artifact_value,
                verdict=normalized_verdict,
            )
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
        self._record_activity(
            'attack',
            attack_type=attack['type'],
            source=attack['source'],
            severity=attack['severity'],
            description=attack['description'],
        )
        self.recent_attacks.append(attack)

        readable_type = attack['type'].replace('_', ' ').strip().title()
        sev_upper = attack['severity'].upper()
        desc_short = attack['description'] or 'Suspicious activity detected'
        self._render_console_table(
            "🚨 ATTACK DETECTED",
            [
                ("Type", readable_type),
                ("Severity", sev_upper),
                ("Source", attack['source']),
                ("Summary", desc_short),
            ],
        )
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
        self._render_console_table(
            "🛡️ SENTINEL-AI ACTIVITY MONITOR",
            [
                ("State", "Online"),
                ("Report Window", self._humanize_interval(self.update_interval)),
                ("Mode", "Hourly coverage summary"),
            ],
        )
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
        uptime_delta = now - self.start_time
        if uptime_delta.total_seconds() < self.update_interval:
            return

        uptime_str = self._compact_duration(uptime_delta)

        coverage_events = self._coverage_events(now)
        scans_in_window = sum(1 for event in coverage_events if event.get('type') == 'scan')
        threats_in_window = sum(1 for event in coverage_events if event.get('type') in {'threat', 'attack'} and (
            event.get('type') == 'attack' or str(event.get('verdict') or '').lower() in {'malicious', 'suspicious', 'critical'}
        ))
        attacks_in_window = sum(1 for event in coverage_events if event.get('type') == 'attack')
        latest_event_time = coverage_events[-1]['time'] if coverage_events else None
        last_str = self._format_relative_time(now, latest_event_time)

        latest = self._latest_coverage_label(coverage_events)
        latest_label = latest if latest else "No new target in coverage window"
        if latest and latest != self._last_status_latest:
            self._last_status_latest = latest

        self._render_console_table(
            f"◈ MONITOR STATUS · LAST {self._humanize_interval(self.update_interval).upper()}",
            [
                ("Coverage", self._humanize_interval(self.update_interval)),
                ("Uptime", uptime_str),
                ("Scans", scans_in_window),
                ("Threats", threats_in_window),
                ("Attacks", attacks_in_window),
                ("Last Activity", last_str),
                ("Latest", latest_label),
            ],
        )
        sys.stdout.flush()

    @staticmethod
    def _render_console_table(title: str, rows: list[tuple], footer: str | None = None):
        """Render compact readable table with automatic word wrapping."""
        width = max(80, min(136, shutil.get_terminal_size((110, 20)).columns))
        key_width = max((len(str(k)) for k, _ in rows), default=12)
        key_width = max(11, min(24, key_width + 1))
        val_width = max(24, width - key_width - 7)

        top = f"┌{'─' * (width - 2)}┐"
        mid = f"├{'─' * (width - 2)}┤"
        bottom = f"└{'─' * (width - 2)}┘"

        print(top, flush=True)
        print(f"│ {title[:width - 4]:<{width - 4}} │", flush=True)
        print(mid, flush=True)

        for key, value in rows:
            label = str(key)
            value_text = str(value if value is not None else '—')
            wrapped = textwrap.wrap(value_text, width=val_width) or ['—']
            for i, line in enumerate(wrapped):
                left = label if i == 0 else ''
                print(f"│ {left:<{key_width}} │ {line:<{val_width}} │", flush=True)

        if footer:
            print(mid, flush=True)
            for line in textwrap.wrap(str(footer), width=width - 4) or ['']:
                print(f"│ {line:<{width - 4}} │", flush=True)

        print(bottom, flush=True)

    @staticmethod
    def _compact_duration(delta: timedelta) -> str:
        total_seconds = max(0, int(delta.total_seconds()))
        hours, rem = divmod(total_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        if hours > 0:
            return f"{hours}h{minutes:02d}m"
        if minutes > 0:
            return f"{minutes}m{seconds:02d}s"
        return f"{seconds}s"

    @staticmethod
    def _humanize_interval(seconds: int) -> str:
        total_seconds = max(0, int(seconds or 0))
        hours, rem = divmod(total_seconds, 3600)
        minutes, secs = divmod(rem, 60)
        if hours and minutes:
            return f"{hours}h {minutes}m"
        if hours:
            return f"{hours}h"
        if minutes:
            return f"{minutes}m"
        return f"{secs}s"

    @staticmethod
    def _compact_target(value: str) -> str:
        text = str(value or '').strip()
        if not text:
            return 'activity'
        text = text.replace('https://', '').replace('http://', '')
        text = text.rstrip('/')
        if '/' in text:
            text = text.split('/', 1)[0]
        return text[:36]
    
    def print_summary(self):
        """Print final summary"""
        duration = datetime.now(timezone.utc) - self.start_time
        duration_str = str(duration).split('.')[0]
        threat_rate = (
            (self.stats['threats_detected'] / self.stats['scans_performed']) * 100
            if self.stats['scans_performed'] > 0 else 0.0
        )
        self._render_console_table(
            "◈ SESSION SUMMARY",
            [
                ("Uptime", duration_str),
                ("Websites", self.stats['websites_monitored']),
                ("Scans", self.stats['scans_performed']),
                ("Threats", self.stats['threats_detected']),
                ("Attacks", self.stats['attack_events']),
                ("Threat Rate", f"{threat_rate:.1f}%"),
            ],
        )
        sys.stdout.flush()


# Global instance (hourly coverage summaries by default)
terminal_monitor = TerminalActivityMonitor(
    update_interval=max(60, int(os.getenv('SENTINEL_MONITOR_STATUS_INTERVAL', '3600') or 3600))
)
