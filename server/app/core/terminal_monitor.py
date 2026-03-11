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
    
    def __init__(self, update_interval: int = 30):
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
            'threats_detected': 0,
            'last_activity_time': None
        }
        
        # Track last printed stats to detect new activity
        self.last_printed_stats = {
            'websites_monitored': 0,
            'apps_monitored': 0,
            'connections_monitored': 0,
            'scans_performed': 0,
            'threats_detected': 0
        }
        
        # Recent activities for display
        self.recent_websites: Deque[str] = deque(maxlen=5)
        self.recent_apps: Deque[str] = deque(maxlen=5)
        self.recent_threats: Deque[Dict] = deque(maxlen=5)
        
        self.start_time = datetime.now(timezone.utc)
        
    def start(self):
        """Start terminal monitoring"""
        if self.running:
            return
        
        self.running = True
        self.start_time = datetime.utcnow()
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
        self.stats['last_activity_time'] = datetime.utcnow()
        
        activity = f"{domain} [{risk_level}]"
        if activity not in self.recent_websites:
            self.recent_websites.append(activity)
    
    def log_app_activity(self, app_name: str, risk_level: str = 'LOW'):
        """Log application activity"""
        self.stats['apps_monitored'] += 1
        self.stats['last_activity_time'] = datetime.utcnow()
        
        activity = f"{app_name} [{risk_level}]"
        if activity not in self.recent_apps:
            self.recent_apps.append(activity)
    
    def log_connection_activity(self):
        """Log network connection"""
        self.stats['connections_monitored'] += 1
        self.stats['last_activity_time'] = datetime.utcnow()
    
    def log_scan_activity(self, artifact_type: str, artifact_value: str, verdict: str):
        """Log threat scan activity"""
        self.stats['scans_performed'] += 1
        self.stats['last_activity_time'] = datetime.utcnow()
        
        if verdict in ['malicious', 'suspicious', 'critical']:
            self.stats['threats_detected'] += 1
            self.recent_threats.append({
                'type': artifact_type,
                'value': artifact_value,
                'verdict': verdict,
                'time': datetime.utcnow()
            })
    
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
        print("📊 Activity monitor active", flush=True)
        sys.stdout.flush()
    
    def _has_new_activity(self):
        """Check if there's been any new activity since last print"""
        return (
            self.stats['websites_monitored'] != self.last_printed_stats['websites_monitored'] or
            self.stats['apps_monitored'] != self.last_printed_stats['apps_monitored'] or
            self.stats['connections_monitored'] != self.last_printed_stats['connections_monitored'] or
            self.stats['scans_performed'] != self.last_printed_stats['scans_performed'] or
            self.stats['threats_detected'] != self.last_printed_stats['threats_detected']
        )
    
    def _update_last_printed_stats(self):
        """Update the last printed stats snapshot"""
        self.last_printed_stats = {
            'websites_monitored': self.stats['websites_monitored'],
            'apps_monitored': self.stats['apps_monitored'],
            'connections_monitored': self.stats['connections_monitored'],
            'scans_performed': self.stats['scans_performed'],
            'threats_detected': self.stats['threats_detected']
        }
    
    def _print_update(self):
        """Print activity update"""
        # Skip if no activity yet
        if (self.stats['websites_monitored'] == 0 and 
            self.stats['apps_monitored'] == 0 and 
            self.stats['scans_performed'] == 0):
            return
        
        # Calculate uptime
        uptime = datetime.utcnow() - self.start_time
        uptime_str = str(uptime).split('.')[0]  # Remove microseconds
        
        # Get time since last activity
        last_activity = "N/A"
        if self.stats['last_activity_time']:
            time_since = datetime.utcnow() - self.stats['last_activity_time']
            if time_since.total_seconds() < 60:
                last_activity = f"{int(time_since.total_seconds())}s ago"
            elif time_since.total_seconds() < 3600:
                last_activity = f"{int(time_since.total_seconds() / 60)}m ago"
            else:
                last_activity = f"{int(time_since.total_seconds() / 3600)}h ago"
        
        latest_website = self.recent_websites[-1] if self.recent_websites else "-"
        latest_threat = self.recent_threats[-1] if self.recent_threats else None
        latest_threat_text = (
            f" | last threat={latest_threat['type'].upper()}:{latest_threat['verdict'].upper()}"
            if latest_threat else ""
        )
        print(
            f"📊 Uptime={uptime_str} | last={last_activity} | websites={self.stats['websites_monitored']} "
            f"| apps={self.stats['apps_monitored']} | scans={self.stats['scans_performed']} "
            f"| threats={self.stats['threats_detected']} | latest={latest_website}{latest_threat_text}",
            flush=True,
        )
        sys.stdout.flush()
    
    def print_summary(self):
        """Print final summary"""
        # Calculate session duration
        duration = datetime.utcnow() - self.start_time
        duration_str = str(duration).split('.')[0]
        threat_rate = (self.stats['threats_detected'] / self.stats['scans_performed']) * 100 if self.stats['scans_performed'] > 0 else 0.0
        print(
            f"📊 Monitor summary | duration={duration_str} | websites={self.stats['websites_monitored']} "
            f"| apps={self.stats['apps_monitored']} | scans={self.stats['scans_performed']} "
            f"| threats={self.stats['threats_detected']} | rate={threat_rate:.1f}%",
            flush=True,
        )
        sys.stdout.flush()


# Global instance
terminal_monitor = TerminalActivityMonitor(update_interval=30)
