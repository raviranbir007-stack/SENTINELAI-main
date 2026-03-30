"""
Enhanced Activity Monitoring Database Schema and Reporting
Comprehensive logging of all monitoring activities with detailed records
"""

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("ActivityDatabase")


class ActivityDatabase:
    """
    Enhanced database for comprehensive activity monitoring
    Stores all activity details for reporting and forensic analysis
    """
    
    def __init__(self, db_path: str = "activity_monitoring.db"):
        # Use stable absolute path to avoid creating different DB files from different CWDs
        if Path(db_path).is_absolute():
            resolved_path = Path(db_path)
        else:
            # server/app/core/activity_database.py -> server/
            server_root = Path(__file__).resolve().parents[2]
            resolved_path = server_root / db_path

        self.db_path = str(resolved_path)
        self._required_tables = {
            "websites",
            "applications",
            "network_connections",
            "file_operations",
            "dns_queries",
            "threat_scans",
            "activity_summary",
        }
        self._schema_lock = Lock()
        self._last_schema_check = datetime.min.replace(tzinfo=timezone.utc)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_enhanced_schema()
        logger.info(f"📊 Activity database initialized: {self.db_path}")

    def _ensure_schema_ready(self, force: bool = False):
        """Ensure expected tables exist; recreate missing schema when needed."""
        now = datetime.now(timezone.utc)
        if not force and (now - self._last_schema_check).total_seconds() < 30:
            return

        with self._schema_lock:
            now = datetime.now(timezone.utc)
            if not force and (now - self._last_schema_check).total_seconds() < 30:
                return

            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                existing = {row[0] for row in cursor.fetchall()}
            finally:
                conn.close()

            missing = self._required_tables - existing
            if missing:
                logger.warning("Activity DB schema drift detected; rebuilding missing tables: %s", sorted(missing))
                self._init_enhanced_schema()

            self._last_schema_check = now

    def _connect(self):
        """Return a database connection after schema verification."""
        self._ensure_schema_ready()
        return sqlite3.connect(self.db_path)
    
    def _init_enhanced_schema(self):
        """Initialize comprehensive database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enhanced websites table with full details
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                title TEXT,
                browser TEXT,
                visit_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT DEFAULT 'LOW',
                risk_score REAL DEFAULT 0.0,
                risk_factors TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                scan_status TEXT DEFAULT 'pending',
                scan_result TEXT,
                threat_verdict TEXT,
                corroboration_sources TEXT,
                response_time_ms INTEGER,
                page_size_kb INTEGER,
                user_agent TEXT,
                referer TEXT,
                session_id TEXT,
                metadata TEXT
            )
        ''')
        
        # Enhanced applications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT NOT NULL,
                app_path TEXT,
                pid INTEGER,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                end_time DATETIME,
                duration_seconds INTEGER,
                risk_level TEXT DEFAULT 'LOW',
                risk_score REAL DEFAULT 0.0,
                risk_factors TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                cpu_usage REAL,
                memory_usage_mb REAL,
                disk_io_mb REAL,
                network_io_mb REAL,
                file_operations_count INTEGER DEFAULT 0,
                network_connections_count INTEGER DEFAULT 0,
                suspicious_behaviors TEXT,
                parent_process TEXT,
                command_line TEXT,
                hash_md5 TEXT,
                hash_sha256 TEXT,
                metadata TEXT
            )
        ''')
        
        # Enhanced network connections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_name TEXT,
                process_name TEXT,
                pid INTEGER,
                local_addr TEXT,
                local_port INTEGER,
                remote_addr TEXT,
                remote_ip TEXT,
                remote_port INTEGER,
                remote_domain TEXT,
                protocol TEXT,
                status TEXT,
                connection_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                duration_seconds INTEGER,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'LOW',
                risk_score REAL DEFAULT 0.0,
                risk_factors TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                geo_location TEXT,
                asn TEXT,
                threat_intel_results TEXT,
                metadata TEXT
            )
        ''')
        
        # File operations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                app_name TEXT,
                pid INTEGER,
                operation_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                file_size_bytes INTEGER,
                file_hash TEXT,
                risk_level TEXT DEFAULT 'LOW',
                risk_factors TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                metadata TEXT
            )
        ''')
        
        # DNS queries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query_domain TEXT NOT NULL,
                query_type TEXT,
                response_ip TEXT,
                query_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                response_time_ms INTEGER,
                source_app TEXT,
                risk_level TEXT DEFAULT 'LOW',
                risk_factors TEXT,
                threat_intel_results TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                metadata TEXT
            )
        ''')
        
        # Threat scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_type TEXT NOT NULL,
                artifact_value TEXT NOT NULL,
                scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                scan_duration_ms INTEGER,
                verdict TEXT,
                confidence REAL,
                threat_level TEXT,
                corroboration_level TEXT,
                source_count INTEGER,
                sources TEXT,
                api_results TEXT,
                threat_indicators TEXT,
                recommendations TEXT,
                flags TEXT,
                is_automated BOOLEAN DEFAULT 1,
                metadata TEXT
            )
        ''')
        
        # Activity summary table (for quick stats)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_summary (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                summary_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                period_start DATETIME,
                period_end DATETIME,
                websites_visited INTEGER DEFAULT 0,
                apps_launched INTEGER DEFAULT 0,
                network_connections INTEGER DEFAULT 0,
                dns_queries INTEGER DEFAULT 0,
                file_operations INTEGER DEFAULT 0,
                threats_detected INTEGER DEFAULT 0,
                scans_performed INTEGER DEFAULT 0,
                high_risk_activities INTEGER DEFAULT 0,
                blocked_activities INTEGER DEFAULT 0,
                summary_data TEXT
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_websites_domain ON websites(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_websites_time ON websites(visit_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_websites_risk ON websites(risk_level)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_apps_name ON applications(app_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_apps_time ON applications(start_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_ip ON network_connections(remote_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_time ON network_connections(connection_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_value ON threat_scans(artifact_value)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_time ON threat_scans(scan_time)')
        
        conn.commit()
        conn.close()
    
    def log_website(self, data: Dict) -> int:
        """Log website visit with full details"""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO websites (
                    url, domain, title, browser, risk_level, risk_score, risk_factors,
                    scan_status, scan_result, threat_verdict, corroboration_sources,
                    response_time_ms, page_size_kb, user_agent, referer, session_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('url'),
                data.get('domain'),
                data.get('title'),
                data.get('browser'),
                data.get('risk_level', 'LOW'),
                data.get('risk_score', 0.0),
                json.dumps(data.get('risk_factors', [])),
                data.get('scan_status', 'pending'),
                json.dumps(data.get('scan_result')),
                data.get('threat_verdict'),
                json.dumps(data.get('corroboration_sources', [])),
                data.get('response_time_ms'),
                data.get('page_size_kb'),
                data.get('user_agent'),
                data.get('referer'),
                data.get('session_id'),
                json.dumps(data.get('metadata', {}))
            ))
            
            record_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return record_id
            
        except Exception as e:
            logger.error(f"Error logging website: {e}")
            return -1
    
    def log_application(self, data: Dict) -> int:
        """Log application activity with full details"""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO applications (
                    app_name, app_path, pid, start_time, risk_level, risk_score, risk_factors,
                    cpu_usage, memory_usage_mb, disk_io_mb, network_io_mb,
                    file_operations_count, network_connections_count, suspicious_behaviors,
                    parent_process, command_line, hash_md5, hash_sha256, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('app_name'),
                data.get('app_path'),
                data.get('pid'),
                data.get('start_time', datetime.now(timezone.utc)),
                data.get('risk_level', 'LOW'),
                data.get('risk_score', 0.0),
                json.dumps(data.get('risk_factors', [])),
                data.get('cpu_usage'),
                data.get('memory_usage_mb'),
                data.get('disk_io_mb'),
                data.get('network_io_mb'),
                data.get('file_operations_count', 0),
                data.get('network_connections_count', 0),
                json.dumps(data.get('suspicious_behaviors', [])),
                data.get('parent_process'),
                data.get('command_line'),
                data.get('hash_md5'),
                data.get('hash_sha256'),
                json.dumps(data.get('metadata', {}))
            ))
            
            record_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return record_id
            
        except sqlite3.OperationalError as e:
            # Self-heal when schema/table is missing in an existing DB file
            if "no such table: applications" in str(e).lower():
                logger.warning("Detected missing applications table; reinitializing activity DB schema")
                try:
                    self._init_enhanced_schema()
                    conn = self._connect()
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO applications (
                            app_name, app_path, pid, start_time, risk_level, risk_score, risk_factors,
                            cpu_usage, memory_usage_mb, disk_io_mb, network_io_mb,
                            file_operations_count, network_connections_count, suspicious_behaviors,
                            parent_process, command_line, hash_md5, hash_sha256, metadata
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        data.get('app_name'),
                        data.get('app_path'),
                        data.get('pid'),
                        data.get('start_time', datetime.now(timezone.utc)),
                        data.get('risk_level', 'LOW'),
                        data.get('risk_score', 0.0),
                        json.dumps(data.get('risk_factors', [])),
                        data.get('cpu_usage'),
                        data.get('memory_usage_mb'),
                        data.get('disk_io_mb'),
                        data.get('network_io_mb'),
                        data.get('file_operations_count', 0),
                        data.get('network_connections_count', 0),
                        json.dumps(data.get('suspicious_behaviors', [])),
                        data.get('parent_process'),
                        data.get('command_line'),
                        data.get('hash_md5'),
                        data.get('hash_sha256'),
                        json.dumps(data.get('metadata', {}))
                    ))
                    record_id = cursor.lastrowid
                    conn.commit()
                    conn.close()
                    return record_id
                except Exception as retry_error:
                    logger.error(f"Error logging application after schema reinit: {retry_error}")
                    return -1
            logger.error(f"Error logging application: {e}")
            return -1

        except Exception as e:
            logger.error(f"Error logging application: {e}")
            return -1
    
    def log_network_connection(self, data: Dict) -> int:
        """Log network connection with full details"""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO network_connections (
                    app_name, process_name, pid, local_addr, local_port,
                    remote_addr, remote_ip, remote_port, remote_domain, protocol, status,
                    bytes_sent, bytes_received, packets_sent, packets_received,
                    risk_level, risk_score, risk_factors, geo_location, asn,
                    threat_intel_results, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('app_name'),
                data.get('process_name'),
                data.get('pid'),
                data.get('local_addr'),
                data.get('local_port'),
                data.get('remote_addr'),
                data.get('remote_ip'),
                data.get('remote_port'),
                data.get('remote_domain'),
                data.get('protocol'),
                data.get('status'),
                data.get('bytes_sent', 0),
                data.get('bytes_received', 0),
                data.get('packets_sent', 0),
                data.get('packets_received', 0),
                data.get('risk_level', 'LOW'),
                data.get('risk_score', 0.0),
                json.dumps(data.get('risk_factors', [])),
                data.get('geo_location'),
                data.get('asn'),
                json.dumps(data.get('threat_intel_results')),
                json.dumps(data.get('metadata', {}))
            ))
            
            record_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return record_id
            
        except Exception as e:
            logger.error(f"Error logging network connection: {e}")
            return -1
    
    def log_threat_scan(self, data: Dict) -> int:
        """Log threat scan with full details"""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threat_scans (
                    artifact_type, artifact_value, scan_duration_ms, verdict, confidence,
                    threat_level, corroboration_level, source_count, sources,
                    api_results, threat_indicators, recommendations, flags,
                    is_automated, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('artifact_type'),
                data.get('artifact_value'),
                data.get('scan_duration_ms'),
                data.get('verdict'),
                data.get('confidence'),
                data.get('threat_level'),
                data.get('corroboration_level'),
                data.get('source_count'),
                json.dumps(data.get('sources', [])),
                json.dumps(data.get('api_results')),
                json.dumps(data.get('threat_indicators', [])),
                json.dumps(data.get('recommendations', [])),
                json.dumps(data.get('flags', {})),
                data.get('is_automated', True),
                json.dumps(data.get('metadata', {}))
            ))
            
            record_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return record_id
            
        except Exception as e:
            logger.error(f"Error logging threat scan: {e}")
            return -1
    
    def get_activity_summary(self, hours: int = 24) -> Dict:
        """Get activity summary for the last N hours"""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            cutoff_time_str = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Websites
            cursor.execute(
                'SELECT COUNT(*) FROM websites WHERE visit_time > ?',
                (cutoff_time_str,)
            )
            websites_count = cursor.fetchone()[0]
            
            # Applications
            cursor.execute(
                'SELECT COUNT(*) FROM applications WHERE start_time > ?',
                (cutoff_time_str,)
            )
            apps_count = cursor.fetchone()[0]
            
            # Network connections
            cursor.execute(
                'SELECT COUNT(*) FROM network_connections WHERE connection_time > ?',
                (cutoff_time_str,)
            )
            connections_count = cursor.fetchone()[0]
            
            # Threat scans
            cursor.execute(
                'SELECT COUNT(*) FROM threat_scans WHERE scan_time > ?',
                (cutoff_time_str,)
            )
            scans_count = cursor.fetchone()[0]
            
            # Threats detected
            cursor.execute(
                'SELECT COUNT(*) FROM threat_scans WHERE scan_time > ? AND verdict IN ("malicious", "suspicious", "critical")',
                (cutoff_time_str,)
            )
            threats_count = cursor.fetchone()[0]
            
            # High risk activities
            cursor.execute(
                'SELECT COUNT(*) FROM websites WHERE visit_time > ? AND risk_level IN ("HIGH", "CRITICAL")',
                (cutoff_time_str,)
            )
            high_risk_websites = cursor.fetchone()[0]
            
            cursor.execute(
                'SELECT COUNT(*) FROM applications WHERE start_time > ? AND risk_level IN ("HIGH", "CRITICAL")',
                (cutoff_time_str,)
            )
            high_risk_apps = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'period_hours': hours,
                'websites_visited': websites_count,
                'applications_launched': apps_count,
                'network_connections': connections_count,
                'threat_scans': scans_count,
                'threats_detected': threats_count,
                'high_risk_activities': high_risk_websites + high_risk_apps,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting activity summary: {e}")
            return {}
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats detected"""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT artifact_type, artifact_value, verdict, confidence, 
                       corroboration_level, source_count, scan_time
                FROM threat_scans
                WHERE verdict IN ('malicious', 'suspicious', 'critical')
                ORDER BY scan_time DESC
                LIMIT ?
            ''', (limit,))
            
            threats = []
            for row in cursor.fetchall():
                threats.append({
                    'type': row[0],
                    'value': row[1],
                    'verdict': row[2],
                    'confidence': row[3],
                    'corroboration': row[4],
                    'sources': row[5],
                    'time': row[6]
                })
            
            conn.close()
            return threats
            
        except Exception as e:
            logger.error(f"Error getting recent threats: {e}")
            return []

    def get_scan_trends(self, hours: int = 24, interval_minutes: int = 60) -> List[Dict]:
        """Return scan counts bucketed into time intervals for trend charts."""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                "SELECT scan_time, verdict FROM threat_scans WHERE scan_time > ? ORDER BY scan_time ASC",
                (cutoff_str,)
            )
            rows = cursor.fetchall()
            conn.close()

            buckets: Dict[str, Dict] = {}
            for (scan_time_str, verdict) in rows:
                try:
                    if isinstance(scan_time_str, str):
                        dt = datetime.fromisoformat(scan_time_str.replace("Z", "+00:00"))
                    else:
                        dt = scan_time_str
                    # Truncate to interval
                    minutes = (dt.minute // interval_minutes) * interval_minutes
                    bucket_dt = dt.replace(minute=minutes, second=0, microsecond=0)
                    bucket_key = bucket_dt.strftime('%Y-%m-%dT%H:%M:00')
                    if bucket_key not in buckets:
                        buckets[bucket_key] = {"timestamp": bucket_key, "total": 0, "threats": 0, "clean": 0}
                    buckets[bucket_key]["total"] += 1
                    if verdict in ("malicious", "suspicious", "critical"):
                        buckets[bucket_key]["threats"] += 1
                    else:
                        buckets[bucket_key]["clean"] += 1
                except Exception:
                    continue

            return sorted(buckets.values(), key=lambda x: x["timestamp"])
        except Exception as e:
            logger.error(f"Error getting scan trends: {e}")
            return []

    def get_threat_distribution(self, hours: int = 24) -> Dict:
        """Return threat type and verdict distribution for the given period."""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute(
                "SELECT artifact_type, COUNT(*) FROM threat_scans WHERE scan_time > ? GROUP BY artifact_type",
                (cutoff_str,)
            )
            by_type = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute(
                "SELECT verdict, COUNT(*) FROM threat_scans WHERE scan_time > ? GROUP BY verdict",
                (cutoff_str,)
            )
            by_verdict = {(row[0] or "unknown"): row[1] for row in cursor.fetchall()}

            cursor.execute(
                "SELECT artifact_type, artifact_value, verdict, confidence, scan_time "
                "FROM threat_scans WHERE scan_time > ? AND verdict IN ('malicious','suspicious','critical') "
                "ORDER BY scan_time DESC LIMIT 20",
                (cutoff_str,)
            )
            top_threats = [
                {"type": r[0], "value": r[1], "verdict": r[2], "confidence": r[3], "time": r[4]}
                for r in cursor.fetchall()
            ]

            conn.close()
            return {"by_type": by_type, "by_verdict": by_verdict, "top_threats": top_threats}
        except Exception as e:
            logger.error(f"Error getting threat distribution: {e}")
            return {"by_type": {}, "by_verdict": {}, "top_threats": []}

    def get_background_stats(self, hours: int = 24) -> Dict:
        """Return comprehensive background monitoring statistics."""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute("SELECT COUNT(*) FROM threat_scans WHERE scan_time > ? AND is_automated=1", (cutoff_str,))
            auto_scans = cursor.fetchone()[0]

            cursor.execute(
                "SELECT COUNT(*) FROM threat_scans WHERE scan_time > ? AND is_automated=1 AND verdict IN ('malicious','suspicious','critical')",
                (cutoff_str,)
            )
            auto_threats = cursor.fetchone()[0]

            # Unique websites monitored: merge website table domains + URL scan hosts
            # so dashboard reflects actual sites observed (not raw row volume).
            site_keys = set()

            cursor.execute("SELECT domain, url FROM websites WHERE visit_time > ?", (cutoff_str,))
            for domain, url in cursor.fetchall():
                dom = (domain or "").strip().lower()
                if not dom and url:
                    try:
                        dom = (urlparse(url).hostname or "").strip().lower()
                    except Exception:
                        dom = ""
                if dom:
                    site_keys.add(dom)

            cursor.execute(
                "SELECT DISTINCT artifact_value FROM threat_scans "
                "WHERE scan_time > ? AND is_automated=1 AND artifact_type='url'",
                (cutoff_str,)
            )
            for (value,) in cursor.fetchall():
                if not value:
                    continue
                host = ""
                try:
                    host = (urlparse(value).hostname or "").strip().lower()
                except Exception:
                    host = ""
                if host:
                    site_keys.add(host)

            sites_visited = len(site_keys)

            cursor.execute("SELECT COUNT(*) FROM network_connections WHERE connection_time > ?", (cutoff_str,))
            net_conns = cursor.fetchone()[0]

            # Also count distinct IPs observed via automated network monitoring
            cursor.execute(
                "SELECT COUNT(DISTINCT artifact_value) FROM threat_scans "
                "WHERE scan_time > ? AND is_automated=1 AND artifact_type='ip'",
                (cutoff_str,)
            )
            net_auto_ips = cursor.fetchone()[0]
            net_conns = net_conns + net_auto_ips

            cursor.execute(
                "SELECT COUNT(DISTINCT artifact_value) FROM threat_scans WHERE scan_time > ? AND is_automated=1",
                (cutoff_str,)
            )
            unique_artifacts = cursor.fetchone()[0]

            cursor.execute(
                "SELECT artifact_type, COUNT(*) FROM threat_scans WHERE scan_time > ? AND is_automated=1 GROUP BY artifact_type",
                (cutoff_str,)
            )
            by_type = {row[0]: row[1] for row in cursor.fetchall()}

            conn.close()
            return {
                "period_hours": hours,
                "automated_scans": auto_scans,
                "automated_threats_found": auto_threats,
                "unique_artifacts_scanned": unique_artifacts,
                "websites_monitored": sites_visited,
                "network_connections_observed": net_conns,
                "breakdown_by_type": by_type,
                "threat_detection_rate": round(auto_threats / auto_scans * 100, 1) if auto_scans else 0.0,
            }
        except Exception as e:
            logger.error(f"Error getting background stats: {e}")
            return {}

    def get_api_usage_summary(self, hours: int = 24, minute_window: int = 1) -> Dict:
        """Return API usage counts from automated scans that actually used external APIs."""
        try:
            from .threat_analyzer import ALL_EXTERNAL_APIS
            conn = self._connect()
            cursor = conn.cursor()
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute(
                "SELECT scan_time, artifact_type, api_results, metadata FROM threat_scans "
                "WHERE scan_time > ? AND is_automated=1",
                (cutoff_str,)
            )
            rows = cursor.fetchall()
            conn.close()

            # Initialize stats for all APIs
            api_coverage_stats = {}
            for api in ALL_EXTERNAL_APIS:
                api_coverage_stats[api["name"]] = {
                    "called": 0,
                    "applicable": 0,
                    "configured": 0,
                    "status": {},
                }

            minute_cutoff = datetime.now(timezone.utc) - timedelta(minutes=minute_window)

            for scan_time, artifact_type, api_results_raw, metadata_raw in rows:
                try:
                    metadata = json.loads(metadata_raw or "{}") if metadata_raw else {}
                except Exception:
                    metadata = {}

                try:
                    api_results = json.loads(api_results_raw or "{}") if api_results_raw else {}
                except Exception:
                    api_results = {}

                api_status = api_results.get("api_status", {})
                apis_called = api_results.get("apis_called", [])

                for api in ALL_EXTERNAL_APIS:
                    name = api["name"]
                    key = api["key"]
                    meta = api_status.get(key, {})
                    # Track if API was called
                    if name in apis_called:
                        api_coverage_stats[name]["called"] += 1
                    # Track if API was applicable
                    if meta.get("applicable") is True:
                        api_coverage_stats[name]["applicable"] += 1
                    # Track if API was configured
                    if meta.get("configured") is True:
                        api_coverage_stats[name]["configured"] += 1
                    # Track status distribution
                    status = meta.get("status", "unknown")
                    api_coverage_stats[name]["status"][status] = api_coverage_stats[name]["status"].get(status, 0) + 1

            return {"api_coverage": api_coverage_stats}
        except Exception as e:
            logger.error(f"Error getting automated API usage summary: {e}")
            return {"api_coverage": {}}

    def get_recent_activity(self, limit: int = 50) -> List[Dict]:
        """Return the most recent background activity entries across all monitored artifact types."""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT artifact_type, artifact_value, verdict, confidence, scan_time, is_automated, threat_indicators "
                "FROM threat_scans ORDER BY scan_time DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            conn.close()
            return [
                {
                    "type": r[0],
                    "value": r[1],
                    "verdict": r[2],
                    "confidence": r[3],
                    "time": r[4],
                    "automated": bool(r[5]),
                    "indicator_count": len(json.loads(r[6] or "[]")) if r[6] else 0,
                }
                for r in rows
            ]
        except Exception as e:
            logger.error(f"Error getting recent activity: {e}")
            return []

    def get_visited_websites(self, limit: int = 50, hours: int = 24) -> List[Dict]:
        """Return recently visited websites with their scan verdicts for the dashboard feed."""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
            cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(
                "SELECT url, domain, title, browser, risk_level, risk_score, "
                "threat_verdict, scan_status, visit_time, metadata "
                "FROM websites WHERE visit_time > ? ORDER BY visit_time DESC LIMIT ?",
                (cutoff_str, limit)
            )
            rows = cursor.fetchall()
            conn.close()
            results = []
            for r in rows:
                url, domain, title, browser, risk_level, risk_score, verdict, status, ts, metadata = r
                display = domain or (urlparse(url).hostname if url else None) or url or "unknown"
                meta_obj = {}
                try:
                    meta_obj = json.loads(metadata or "{}") if isinstance(metadata, str) else (metadata or {})
                except Exception:
                    meta_obj = {}
                host_ip = meta_obj.get("host_ip")
                results.append({
                    "url": url or "",
                    "domain": display,
                    "host_ip": host_ip,
                    "title": title or "",
                    "browser": browser or "unknown",
                    "verdict": (verdict or "unknown").lower(),
                    "risk_level": (risk_level or "LOW").upper(),
                    "confidence": round(float(risk_score or 0.0), 1),
                    "scan_status": status or "pending",
                    "time": ts,
                })
            return results
        except Exception as e:
            logger.error(f"Error getting visited websites: {e}")
            return []

    def get_full_report_data(self, hours: int = 24) -> Dict:
        """Get comprehensive data for report generation"""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            # Get all activities
            cursor.execute(
                'SELECT * FROM websites WHERE visit_time > ? ORDER BY visit_time DESC',
                (cutoff_time,)
            )
            websites = [dict(zip([col[0] for col in cursor.description], row)) 
                       for row in cursor.fetchall()]
            
            cursor.execute(
                'SELECT * FROM applications WHERE start_time > ? ORDER BY start_time DESC',
                (cutoff_time,)
            )
            applications = [dict(zip([col[0] for col in cursor.description], row)) 
                           for row in cursor.fetchall()]
            
            cursor.execute(
                'SELECT * FROM network_connections WHERE connection_time > ? ORDER BY connection_time DESC',
                (cutoff_time,)
            )
            connections = [dict(zip([col[0] for col in cursor.description], row)) 
                          for row in cursor.fetchall()]
            
            cursor.execute(
                'SELECT * FROM threat_scans WHERE scan_time > ? ORDER BY scan_time DESC',
                (cutoff_time,)
            )
            scans = [dict(zip([col[0] for col in cursor.description], row)) 
                    for row in cursor.fetchall()]
            
            conn.close()
            
            return {
                'websites': websites,
                'applications': applications,
                'connections': connections,
                'scans': scans,
                'summary': self.get_activity_summary(hours)
            }
            
        except Exception as e:
            logger.error(f"Error getting report data: {e}")
            return {}


# Global instance
activity_db = ActivityDatabase()
