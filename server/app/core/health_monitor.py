"""
Enhanced Dashboard Health Monitoring System
Tracks client connectivity, alert loads, and system health metrics
"""

import asyncio
import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ClientHealthStatus:
    client_id: str
    last_heartbeat: Optional[float] = None
    status: str = "unknown"  # online, offline, degraded
    alerts_sent: int = 0
    alerts_acknowledged: int = 0
    quarantine_actions: int = 0
    threat_detections: int = 0
    api_failures: int = 0
    last_activity: Optional[float] = None
    version: Optional[str] = None
    os_info: Optional[Dict] = None


@dataclass
class SystemHealthMetrics:
    total_clients: int = 0
    online_clients: int = 0
    offline_clients: int = 0
    degraded_clients: int = 0
    total_alerts_today: int = 0
    unacknowledged_alerts: int = 0
    active_quarantines: int = 0
    system_load: float = 0.0
    memory_usage_percent: float = 0.0
    disk_usage_percent: float = 0.0
    api_response_time_avg: float = 0.0
    threat_detection_rate: float = 0.0  # detections per minute
    alert_acknowledgment_rate: float = 0.0  # percentage


class DashboardHealthMonitor:
    """Enhanced health monitoring for dashboard with client tracking and metrics"""

    def __init__(self):
        self.client_health: Dict[str, ClientHealthStatus] = {}
        self.system_metrics = SystemHealthMetrics()

        # Rolling metrics (last 24 hours)
        self.alert_history = deque(maxlen=1440)  # 1 reading per minute
        self.api_response_times = deque(maxlen=1000)
        self.threat_detection_counts = deque(maxlen=1440)

        # Configuration
        self.heartbeat_timeout = 300  # 5 minutes
        self.degraded_threshold = 600  # 10 minutes
        self.metrics_update_interval = 60  # 1 minute

        # Background task
        self._monitoring_task: Optional[asyncio.Task] = None
        self._running = False

    async def start_monitoring(self):
        """Start the health monitoring background task"""
        if self._running:
            return

        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitor_loop())
        logger.info("Dashboard health monitoring started")

    async def stop_monitoring(self):
        """Stop the health monitoring background task"""
        self._running = False
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        logger.info("Dashboard health monitoring stopped")

    async def _monitor_loop(self):
        """Main monitoring loop"""
        while self._running:
            try:
                await self._update_system_metrics()
                await self._update_client_statuses()
                await self._cleanup_old_data()

                # Update rolling metrics
                current_time = time.time()
                self.alert_history.append((current_time, self.system_metrics.total_alerts_today))
                self.threat_detection_counts.append((current_time, self.system_metrics.threat_detection_rate))

                await asyncio.sleep(self.metrics_update_interval)

            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(30)  # Wait before retrying

    async def _update_system_metrics(self):
        """Update system-wide health metrics"""
        try:
            # Get system resource usage
            import psutil
            self.system_metrics.system_load = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0
            self.system_metrics.memory_usage_percent = psutil.virtual_memory().percent
            self.system_metrics.disk_usage_percent = psutil.disk_usage('/').percent

        except ImportError:
            # psutil not available
            pass
        except Exception as e:
            logger.warning(f"Failed to update system metrics: {e}")

        # Calculate API response time average
        if self.api_response_times:
            self.system_metrics.api_response_time_avg = sum(self.api_response_times) / len(self.api_response_times)

        # Calculate threat detection rate (detections per minute over last hour)
        one_hour_ago = time.time() - 3600
        recent_detections = [count for ts, count in self.threat_detection_counts if ts > one_hour_ago]
        if recent_detections:
            self.system_metrics.threat_detection_rate = sum(recent_detections) / max(1, len(recent_detections))

        # Calculate alert acknowledgment rate
        total_alerts = self.system_metrics.total_alerts_today
        if total_alerts > 0:
            acknowledged = sum(client.alerts_acknowledged for client in self.client_health.values())
            self.system_metrics.alert_acknowledgment_rate = (acknowledged / total_alerts) * 100

    async def _update_client_statuses(self):
        """Update client health statuses based on heartbeat data"""
        current_time = time.time()

        for client_id, health in self.client_health.items():
            if health.last_heartbeat:
                time_since_heartbeat = current_time - health.last_heartbeat

                if time_since_heartbeat > self.degraded_threshold:
                    health.status = "offline"
                elif time_since_heartbeat > self.heartbeat_timeout:
                    health.status = "degraded"
                else:
                    health.status = "online"
            else:
                # No heartbeat ever received
                health.status = "unknown"

        # Update summary counts
        self.system_metrics.total_clients = len(self.client_health)
        self.system_metrics.online_clients = sum(1 for h in self.client_health.values() if h.status == "online")
        self.system_metrics.offline_clients = sum(1 for h in self.client_health.values() if h.status == "offline")
        self.system_metrics.degraded_clients = sum(1 for h in self.client_health.values() if h.status == "degraded")

    async def _cleanup_old_data(self):
        """Clean up old client health data"""
        current_time = time.time()
        cutoff_time = current_time - (24 * 3600)  # 24 hours

        # Remove clients with no activity for 24 hours
        to_remove = []
        for client_id, health in self.client_health.items():
            if health.last_activity and health.last_activity < cutoff_time:
                to_remove.append(client_id)

        for client_id in to_remove:
            del self.client_health[client_id]
            logger.info(f"Removed inactive client from health monitoring: {client_id}")

    def record_client_heartbeat(self, client_id: str, client_info: Dict):
        """Record a client heartbeat"""
        current_time = time.time()

        if client_id not in self.client_health:
            self.client_health[client_id] = ClientHealthStatus(client_id=client_id)

        health = self.client_health[client_id]
        health.last_heartbeat = current_time
        health.last_activity = current_time
        health.version = client_info.get("version")
        health.os_info = client_info.get("os_info")

        logger.debug(f"Client heartbeat recorded: {client_id}")

    def record_alert_sent(self, client_id: str):
        """Record an alert sent to a client"""
        if client_id not in self.client_health:
            self.client_health[client_id] = ClientHealthStatus(client_id=client_id)

        self.client_health[client_id].alerts_sent += 1
        self.system_metrics.total_alerts_today += 1

    def record_alert_acknowledged(self, client_id: str):
        """Record an alert acknowledged by a client"""
        if client_id in self.client_health:
            self.client_health[client_id].alerts_acknowledged += 1

    def record_quarantine_action(self, client_id: str):
        """Record a quarantine action by a client"""
        if client_id not in self.client_health:
            self.client_health[client_id] = ClientHealthStatus(client_id=client_id)

        self.client_health[client_id].quarantine_actions += 1
        self.system_metrics.active_quarantines += 1

    def record_threat_detection(self, client_id: str):
        """Record a threat detection by a client"""
        if client_id not in self.client_health:
            self.client_health[client_id] = ClientHealthStatus(client_id=client_id)

        self.client_health[client_id].threat_detections += 1

    def record_api_failure(self, client_id: str):
        """Record an API failure for a client"""
        if client_id not in self.client_health:
            self.client_health[client_id] = ClientHealthStatus(client_id=client_id)

        self.client_health[client_id].api_failures += 1

    def record_api_response_time(self, response_time: float):
        """Record API response time for performance monitoring"""
        self.api_response_times.append(response_time)

    def get_health_status(self) -> Dict:
        """Get comprehensive health status for dashboard"""
        current_time = time.time()

        # Calculate health score (0-100)
        health_score = self._calculate_health_score()

        # Get client status summary
        client_summary = {
            "total": self.system_metrics.total_clients,
            "online": self.system_metrics.online_clients,
            "offline": self.system_metrics.offline_clients,
            "degraded": self.system_metrics.degraded_clients,
            "unknown": sum(1 for h in self.client_health.values() if h.status == "unknown")
        }

        # Get system status
        system_status = {
            "load": round(self.system_metrics.system_load, 2),
            "memory_percent": round(self.system_metrics.memory_usage_percent, 1),
            "disk_percent": round(self.system_metrics.disk_usage_percent, 1),
            "api_response_time_avg": round(self.system_metrics.api_response_time_avg, 2),
            "threat_detection_rate": round(self.system_metrics.threat_detection_rate, 2),
            "alert_acknowledgment_rate": round(self.system_metrics.alert_acknowledgment_rate, 1)
        }

        # Get alert status
        alert_status = {
            "total_today": self.system_metrics.total_alerts_today,
            "unacknowledged": self.system_metrics.unacknowledged_alerts,
            "acknowledgment_rate": round(self.system_metrics.alert_acknowledgment_rate, 1)
        }

        # Get quarantine status
        quarantine_status = {
            "active": self.system_metrics.active_quarantines
        }

        return {
            "health_score": health_score,
            "timestamp": datetime.fromtimestamp(current_time).isoformat(),
            "clients": client_summary,
            "system": system_status,
            "alerts": alert_status,
            "quarantine": quarantine_status,
            "client_details": [asdict(health) for health in self.client_health.values()]
        }

    def _calculate_health_score(self) -> int:
        """Calculate overall system health score (0-100)"""
        score = 100

        # Client connectivity (40% weight)
        if self.system_metrics.total_clients > 0:
            online_ratio = self.system_metrics.online_clients / self.system_metrics.total_clients
            connectivity_score = online_ratio * 40
            score -= (40 - connectivity_score)

        # System resources (30% weight)
        resource_score = 30
        if self.system_metrics.memory_usage_percent > 90:
            resource_score -= 10
        elif self.system_metrics.memory_usage_percent > 80:
            resource_score -= 5

        if self.system_metrics.disk_usage_percent > 95:
            resource_score -= 10
        elif self.system_metrics.disk_usage_percent > 90:
            resource_score -= 5

        if self.system_metrics.system_load > 8:
            resource_score -= 5
        elif self.system_metrics.system_load > 4:
            resource_score -= 2

        score -= (30 - resource_score)

        # Alert management (20% weight)
        alert_score = 20
        if self.system_metrics.alert_acknowledgment_rate < 50:
            alert_score -= 10
        elif self.system_metrics.alert_acknowledgment_rate < 75:
            alert_score -= 5

        # High alert volume penalty
        if self.system_metrics.total_alerts_today > 100:
            alert_score -= 5

        score -= (20 - alert_score)

        # API performance (10% weight)
        api_score = 10
        if self.system_metrics.api_response_time_avg > 5.0:
            api_score -= 5
        elif self.system_metrics.api_response_time_avg > 2.0:
            api_score -= 2

        score -= (10 - api_score)

        return max(0, min(100, int(score)))

    def get_alert_load_status(self) -> str:
        """Get alert load status for dashboard display"""
        alerts_per_hour = self.system_metrics.total_alerts_today

        if alerts_per_hour > 50:
            return "Critical"
        elif alerts_per_hour > 20:
            return "High"
        elif alerts_per_hour > 5:
            return "Medium"
        else:
            return "Low"

    def get_client_connectivity_status(self) -> str:
        """Get client connectivity status"""
        if self.system_metrics.total_clients == 0:
            return "No Clients"

        online_ratio = self.system_metrics.online_clients / self.system_metrics.total_clients

        if online_ratio >= 0.9:
            return "Excellent"
        elif online_ratio >= 0.75:
            return "Good"
        elif online_ratio >= 0.5:
            return "Fair"
        else:
            return "Poor"


# Global health monitor instance
health_monitor = DashboardHealthMonitor()