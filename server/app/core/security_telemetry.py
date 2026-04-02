import hashlib
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional, List, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitBreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class EnhancedSecurityTelemetryStore:
    """Enhanced security telemetry with improved API failure handling and recovery"""

    def __init__(self, db_path: str = "security_telemetry.db"):
        base = Path(__file__).resolve().parents[2]
        self.db_path = str((base / db_path).resolve())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._init_schema()

        # Circuit breaker configuration
        self._circuit_configs = {
            "default": {
                "failure_threshold": 5,
                "recovery_timeout": 60,  # seconds
                "success_threshold": 3,  # successes needed to close circuit
                "timeout_threshold": 3
            }
        }

        # In-memory circuit states
        self._circuit_states: Dict[str, Dict] = {}

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_schema(self):
        conn = self._connect()
        cur = conn.cursor()

        # Enhanced API quality metrics
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS api_quality_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_name TEXT NOT NULL,
                input_type TEXT,
                status TEXT NOT NULL,
                latency_ms REAL DEFAULT 0,
                confidence REAL,
                verdict TEXT,
                is_timeout INTEGER DEFAULT 0,
                is_false_positive INTEGER DEFAULT 0,
                retry_count INTEGER DEFAULT 0,
                circuit_breaker_state TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Enhanced circuit breaker state
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS api_circuit_state (
                api_name TEXT PRIMARY KEY,
                state TEXT DEFAULT 'closed',
                fail_count INTEGER DEFAULT 0,
                timeout_count INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                opened_until_epoch REAL DEFAULT 0,
                last_failure_epoch REAL DEFAULT 0,
                last_success_epoch REAL DEFAULT 0,
                consecutive_successes INTEGER DEFAULT 0,
                total_calls INTEGER DEFAULT 0,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # API failure patterns for analysis
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS api_failure_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_name TEXT NOT NULL,
                failure_type TEXT NOT NULL,
                error_message TEXT,
                input_type TEXT,
                pattern_hash TEXT,
                frequency INTEGER DEFAULT 1,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Recovery actions tracking
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS api_recovery_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                success INTEGER DEFAULT 0,
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        conn.commit()
        conn.close()

    def record_api_metric(self, api_name: str, input_type: str, status: str,
                         latency_ms: float = 0.0, is_timeout: bool = False,
                         retry_count: int = 0) -> None:
        """Record enhanced API call metrics with circuit breaker state"""
        with self._lock:
            conn = self._connect()
            cur = conn.cursor()

            # Get current circuit state
            circuit_state = self.get_circuit_state(api_name)
            circuit_state_str = circuit_state.get("state", "closed")

            cur.execute(
                """
                INSERT INTO api_quality_metrics
                (api_name, input_type, status, latency_ms, is_timeout, retry_count, circuit_breaker_state)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (api_name, input_type, status, latency_ms, int(is_timeout), retry_count, circuit_state_str)
            )

            # Update circuit breaker state based on result
            self._update_circuit_state(api_name, status, is_timeout)

            conn.commit()
            conn.close()

    def _update_circuit_state(self, api_name: str, status: str, is_timeout: bool):
        """Update circuit breaker state based on API call result"""
        current_time = time.time()
        config = self._circuit_configs.get(api_name, self._circuit_configs["default"])

        # Get current state
        state = self.get_circuit_state(api_name)
        current_state = state.get("state", CircuitBreakerState.CLOSED.value)
        fail_count = state.get("fail_count", 0)
        timeout_count = state.get("timeout_count", 0)
        success_count = state.get("success_count", 0)
        consecutive_successes = state.get("consecutive_successes", 0)
        opened_until = state.get("opened_until_epoch", 0)

        # Update counters
        if status in ["error", "rate_limited", "quota_exceeded"]:
            fail_count += 1
            consecutive_successes = 0
            state["last_failure_epoch"] = current_time
            if is_timeout:
                timeout_count += 1
        elif status == "checked":
            success_count += 1
            consecutive_successes += 1
            state["last_success_epoch"] = current_time
        else:
            # Unknown status, don't change counters
            pass

        # Determine new state
        new_state = current_state

        if current_state == CircuitBreakerState.CLOSED.value:
            # Check if we should open the circuit
            if fail_count >= config["failure_threshold"] or timeout_count >= config["timeout_threshold"]:
                new_state = CircuitBreakerState.OPEN.value
                opened_until = current_time + config["recovery_timeout"]
                logger.warning(f"Circuit breaker opened for {api_name} (failures: {fail_count}, timeouts: {timeout_count})")

        elif current_state == CircuitBreakerState.OPEN.value:
            # Check if recovery timeout has passed
            if current_time >= opened_until:
                new_state = CircuitBreakerState.HALF_OPEN.value
                consecutive_successes = 0  # Reset for half-open state
                logger.info(f"Circuit breaker half-open for {api_name}")

        elif current_state == CircuitBreakerState.HALF_OPEN.value:
            # Check if we have enough consecutive successes to close
            if consecutive_successes >= config["success_threshold"]:
                new_state = CircuitBreakerState.CLOSED.value
                fail_count = 0  # Reset failure count
                timeout_count = 0
                logger.info(f"Circuit breaker closed for {api_name}")
            elif fail_count > 0:
                # Failure in half-open state, go back to open
                new_state = CircuitBreakerState.OPEN.value
                opened_until = current_time + config["recovery_timeout"]
                logger.warning(f"Circuit breaker re-opened for {api_name} after half-open failure")

        # Update state
        state.update({
            "state": new_state,
            "fail_count": fail_count,
            "timeout_count": timeout_count,
            "success_count": success_count,
            "consecutive_successes": consecutive_successes,
            "opened_until_epoch": opened_until,
            "total_calls": state.get("total_calls", 0) + 1,
            "updated_at": datetime.now(timezone.utc).isoformat()
        })

        # Persist to database
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO api_circuit_state
            (api_name, state, fail_count, timeout_count, success_count, consecutive_successes,
             opened_until_epoch, last_failure_epoch, last_success_epoch, total_calls, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (api_name, new_state, fail_count, timeout_count, success_count, consecutive_successes,
             opened_until, state.get("last_failure_epoch", 0), state.get("last_success_epoch", 0),
             state["total_calls"], state["updated_at"])
        )
        conn.commit()
        conn.close()

        self._circuit_states[api_name] = state

    def get_circuit_state(self, api_name: str) -> Dict[str, Any]:
        """Get current circuit breaker state for an API"""
        if api_name in self._circuit_states:
            return self._circuit_states[api_name].copy()

        # Load from database
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM api_circuit_state WHERE api_name = ?", (api_name,))
        row = cur.fetchone()
        conn.close()

        if row:
            state = {
                "api_name": row[0],
                "state": row[1],
                "fail_count": row[2],
                "timeout_count": row[3],
                "success_count": row[4],
                "consecutive_successes": row[5],
                "opened_until_epoch": row[6],
                "last_failure_epoch": row[7] or 0,
                "last_success_epoch": row[8] or 0,
                "total_calls": row[9] or 0,
                "updated_at": row[10]
            }
        else:
            # Default state
            state = {
                "api_name": api_name,
                "state": CircuitBreakerState.CLOSED.value,
                "fail_count": 0,
                "timeout_count": 0,
                "success_count": 0,
                "consecutive_successes": 0,
                "opened_until_epoch": 0,
                "last_failure_epoch": 0,
                "last_success_epoch": 0,
                "total_calls": 0,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }

        self._circuit_states[api_name] = state
        return state.copy()

    def should_attempt_call(self, api_name: str) -> Tuple[bool, str]:
        """Check if an API call should be attempted based on circuit breaker state"""
        state = self.get_circuit_state(api_name)
        current_state = state.get("state", CircuitBreakerState.CLOSED.value)
        current_time = time.time()

        if current_state == CircuitBreakerState.OPEN.value:
            opened_until = state.get("opened_until_epoch", 0)
            if current_time < opened_until:
                remaining = int(opened_until - current_time)
                return False, f"Circuit breaker open, retry in {remaining}s"
            else:
                # Transition to half-open
                self._update_circuit_state(api_name, "half_open_check", False)
                return True, "Circuit breaker half-open, attempting call"

        return True, "OK"

    def record_failure_pattern(self, api_name: str, failure_type: str,
                              error_message: str, input_type: str):
        """Record API failure patterns for analysis"""
        pattern_hash = hashlib.sha256(
            f"{api_name}:{failure_type}:{error_message[:100]}:{input_type}".encode()
        ).hexdigest()[:16]

        with self._lock:
            conn = self._connect()
            cur = conn.cursor()

            # Check if pattern exists
            cur.execute(
                "SELECT id, frequency FROM api_failure_patterns WHERE pattern_hash = ?",
                (pattern_hash,)
            )
            existing = cur.fetchone()

            if existing:
                # Update existing pattern
                cur.execute(
                    "UPDATE api_failure_patterns SET frequency = frequency + 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                    (existing[0],)
                )
            else:
                # Insert new pattern
                cur.execute(
                    """
                    INSERT INTO api_failure_patterns
                    (api_name, failure_type, error_message, input_type, pattern_hash)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (api_name, failure_type, error_message, input_type, pattern_hash)
                )

            conn.commit()
            conn.close()

    def get_failure_patterns(self, api_name: str, limit: int = 10) -> List[Dict]:
        """Get failure patterns for an API"""
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT failure_type, error_message, input_type, frequency, first_seen, last_seen
            FROM api_failure_patterns
            WHERE api_name = ?
            ORDER BY frequency DESC, last_seen DESC
            LIMIT ?
            """,
            (api_name, limit)
        )
        rows = cur.fetchall()
        conn.close()

        return [
            {
                "failure_type": row[0],
                "error_message": row[1],
                "input_type": row[2],
                "frequency": row[3],
                "first_seen": row[4],
                "last_seen": row[5]
            }
            for row in rows
        ]

    def record_recovery_action(self, api_name: str, action_type: str,
                              success: bool, details: str = ""):
        """Record recovery actions taken"""
        with self._lock:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO api_recovery_actions
                (api_name, action_type, success, details)
                VALUES (?, ?, ?, ?)
                """,
                (api_name, action_type, int(success), details)
            )
            conn.commit()
            conn.close()

    def get_api_health_score(self, api_name: str, window_hours: int = 24) -> float:
        """Calculate API health score (0-1) based on recent performance"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=window_hours)

        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT status, is_timeout, latency_ms
            FROM api_quality_metrics
            WHERE api_name = ? AND created_at >= ?
            """,
            (api_name, cutoff_time.isoformat())
        )
        rows = cur.fetchall()
        conn.close()

        if not rows:
            return 1.0  # No data = assume healthy

        total_calls = len(rows)
        successful_calls = sum(1 for row in rows if row[0] == "checked")
        timeout_calls = sum(1 for row in rows if row[1] == 1)

        # Calculate weighted score
        success_rate = successful_calls / total_calls
        timeout_penalty = min(0.5, (timeout_calls / total_calls) * 0.5)

        # Latency penalty (calls over 5 seconds get penalty)
        slow_calls = sum(1 for row in rows if row[2] and row[2] > 5000)
        latency_penalty = min(0.3, (slow_calls / total_calls) * 0.3)

        health_score = success_rate - timeout_penalty - latency_penalty
        return max(0.0, min(1.0, health_score))

    def get_circuit_breaker_stats(self) -> Dict[str, Dict]:
        """Get circuit breaker statistics for all APIs"""
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM api_circuit_state")
        rows = cur.fetchall()
        conn.close()

        stats = {}
        for row in rows:
            api_name = row[0]
            stats[api_name] = {
                "state": row[1],
                "fail_count": row[2],
                "timeout_count": row[3],
                "success_count": row[4],
                "consecutive_successes": row[5],
                "total_calls": row[9] or 0,
                "health_score": self.get_api_health_score(api_name),
                "failure_patterns": self.get_failure_patterns(api_name, 3)
            }

        return stats


class EnhancedSecurityTelemetryStore:
    """Persist API quality, correlation signals, baseline stats, feedback, and immutable audit chain."""

    def __init__(self, db_path: str = "security_telemetry.db"):
        base = Path(__file__).resolve().parents[2]
        self.db_path = str((base / db_path).resolve())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._init_schema()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_schema(self):
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS api_quality_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_name TEXT NOT NULL,
                input_type TEXT,
                status TEXT NOT NULL,
                latency_ms REAL DEFAULT 0,
                confidence REAL,
                verdict TEXT,
                is_timeout INTEGER DEFAULT 0,
                is_false_positive INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS api_circuit_state (
                api_name TEXT PRIMARY KEY,
                fail_count INTEGER DEFAULT 0,
                timeout_count INTEGER DEFAULT 0,
                opened_until_epoch REAL DEFAULT 0,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS correlation_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                event_value TEXT,
                verdict TEXT,
                confidence REAL,
                metadata TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS behavior_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                principal TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                hour_bucket INTEGER NOT NULL,
                sample_count INTEGER DEFAULT 0,
                mean_rate REAL DEFAULT 0,
                m2 REAL DEFAULT 0,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(principal, artifact_type, hour_bucket)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS false_positive_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                input_type TEXT,
                verdict TEXT,
                analyst_label TEXT,
                weight REAL DEFAULT 1.0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS immutable_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                actor TEXT,
                target TEXT,
                details TEXT,
                prev_hash TEXT,
                entry_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_api_quality_name_time ON api_quality_metrics(api_name, created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_corr_time ON correlation_events(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_fp_fingerprint ON false_positive_feedback(fingerprint, created_at)")
        conn.commit()
        conn.close()

    def record_api_metric(
        self,
        api_name: str,
        input_type: str,
        status: str,
        latency_ms: float,
        confidence: Optional[float] = None,
        verdict: Optional[str] = None,
        is_timeout: bool = False,
        is_false_positive: bool = False,
    ) -> None:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO api_quality_metrics(
                api_name, input_type, status, latency_ms, confidence, verdict, is_timeout, is_false_positive
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                api_name,
                input_type,
                status,
                float(latency_ms or 0.0),
                confidence,
                verdict,
                1 if is_timeout else 0,
                1 if is_false_positive else 0,
            ),
        )
        conn.commit()
        conn.close()

    def get_api_health_score(self, api_name: str, window_hours: int = 24) -> float:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
              COUNT(*),
              SUM(CASE WHEN status='checked' THEN 1 ELSE 0 END),
              AVG(latency_ms),
              SUM(CASE WHEN is_timeout=1 THEN 1 ELSE 0 END),
              SUM(CASE WHEN is_false_positive=1 THEN 1 ELSE 0 END)
            FROM api_quality_metrics
            WHERE api_name=? AND created_at > ?
            """,
            (api_name, cutoff),
        )
        total, ok, avg_latency, timeouts, fps = cur.fetchone()
        conn.close()

        total = int(total or 0)
        if total == 0:
            return 0.75

        success_rate = float(ok or 0) / total
        timeout_rate = float(timeouts or 0) / total
        fp_rate = float(fps or 0) / total
        latency_penalty = min(0.25, max(0.0, (float(avg_latency or 0.0) - 1200.0) / 8000.0))

        score = 1.0
        score -= (1.0 - success_rate) * 0.45
        score -= timeout_rate * 0.25
        score -= fp_rate * 0.20
        score -= latency_penalty
        return max(0.0, min(1.0, score))

    def api_usage_count(self, api_name: str, window_hours: int = 24) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM api_quality_metrics WHERE api_name=? AND created_at > ?",
            (api_name, cutoff),
        )
        total = int(cur.fetchone()[0] or 0)
        conn.close()
        return total

    def get_circuit_state(self, api_name: str) -> Dict[str, Any]:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute("SELECT fail_count, timeout_count, opened_until_epoch FROM api_circuit_state WHERE api_name=?", (api_name,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return {"fail_count": 0, "timeout_count": 0, "opened_until_epoch": 0.0}
        return {"fail_count": int(row[0] or 0), "timeout_count": int(row[1] or 0), "opened_until_epoch": float(row[2] or 0.0)}

    def update_circuit_state(self, api_name: str, fail_delta: int = 0, timeout_delta: int = 0, opened_until_epoch: Optional[float] = None, reset: bool = False) -> None:
        state = self.get_circuit_state(api_name)
        fail_count = 0 if reset else max(0, state["fail_count"] + fail_delta)
        timeout_count = 0 if reset else max(0, state["timeout_count"] + timeout_delta)
        opened_until = float(opened_until_epoch if opened_until_epoch is not None else state["opened_until_epoch"])

        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO api_circuit_state(api_name, fail_count, timeout_count, opened_until_epoch)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(api_name) DO UPDATE SET
                fail_count=excluded.fail_count,
                timeout_count=excluded.timeout_count,
                opened_until_epoch=excluded.opened_until_epoch,
                updated_at=CURRENT_TIMESTAMP
            """,
            (api_name, fail_count, timeout_count, opened_until),
        )
        conn.commit()
        conn.close()

    def record_correlation_event(self, event_type: str, event_value: str, verdict: str, confidence: float, metadata: Optional[Dict[str, Any]] = None) -> None:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO correlation_events(event_type, event_value, verdict, confidence, metadata) VALUES(?, ?, ?, ?, ?)",
            (event_type, event_value, verdict, float(confidence or 0.0), json.dumps(metadata or {})),
        )
        conn.commit()
        conn.close()

    def get_recent_events(self, minutes: int = 45):
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT event_type, event_value, verdict, confidence, metadata, created_at FROM correlation_events WHERE created_at > ? ORDER BY created_at DESC",
            (cutoff,),
        )
        rows = cur.fetchall()
        conn.close()
        events = []
        for e_type, e_value, verdict, conf, metadata, created_at in rows:
            try:
                meta = json.loads(metadata or "{}") if metadata else {}
            except Exception:
                meta = {}
            events.append({
                "type": e_type,
                "value": e_value,
                "verdict": verdict,
                "confidence": float(conf or 0.0),
                "metadata": meta,
                "created_at": created_at,
            })
        return events

    def baseline_anomaly_score(self, principal: str, artifact_type: str, count_in_window: int) -> Dict[str, float]:
        hour_bucket = datetime.now(timezone.utc).hour
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT sample_count, mean_rate, m2 FROM behavior_baseline WHERE principal=? AND artifact_type=? AND hour_bucket=?",
            (principal, artifact_type, hour_bucket),
        )
        row = cur.fetchone()

        if row:
            n, mean, m2 = int(row[0] or 0), float(row[1] or 0.0), float(row[2] or 0.0)
        else:
            n, mean, m2 = 0, 0.0, 0.0

        x = float(max(0, count_in_window))
        n2 = n + 1
        delta = x - mean
        mean2 = mean + (delta / n2)
        delta2 = x - mean2
        m2_2 = m2 + (delta * delta2)

        variance = (m2 / (n - 1)) if n > 1 else 1.0
        std = max(1.0, variance ** 0.5)
        z = (x - mean) / std if n > 3 else 0.0

        cur.execute(
            """
            INSERT INTO behavior_baseline(principal, artifact_type, hour_bucket, sample_count, mean_rate, m2)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(principal, artifact_type, hour_bucket) DO UPDATE SET
                sample_count=excluded.sample_count,
                mean_rate=excluded.mean_rate,
                m2=excluded.m2,
                updated_at=CURRENT_TIMESTAMP
            """,
            (principal, artifact_type, hour_bucket, n2, mean2, m2_2),
        )
        conn.commit()
        conn.close()

        return {
            "z_score": float(z),
            "mean": float(mean),
            "std": float(std),
            "sample_count": float(n),
            "anomalous": 1.0 if z >= 2.5 else 0.0,
        }

    def record_false_positive_feedback(self, fingerprint: str, input_type: str, verdict: str, analyst_label: str, weight: float = 1.0) -> None:
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO false_positive_feedback(fingerprint, input_type, verdict, analyst_label, weight) VALUES(?, ?, ?, ?, ?)",
            (fingerprint, input_type, verdict, analyst_label, float(weight)),
        )
        conn.commit()
        conn.close()

    def false_positive_score(self, fingerprint: str, lookback_days: int = 30) -> float:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            "SELECT COALESCE(SUM(weight),0) FROM false_positive_feedback WHERE fingerprint=? AND analyst_label='false_positive' AND created_at > ?",
            (fingerprint, cutoff),
        )
        fp = float(cur.fetchone()[0] or 0.0)
        cur.execute(
            "SELECT COALESCE(SUM(weight),0) FROM false_positive_feedback WHERE fingerprint=? AND analyst_label IN ('malicious','true_positive') AND created_at > ?",
            (fingerprint, cutoff),
        )
        tp = float(cur.fetchone()[0] or 0.0)
        conn.close()
        denom = fp + tp + 1.0
        return max(0.0, min(1.0, fp / denom))

    def decayed_feedback_stats(
        self,
        fingerprint: str,
        lookback_days: int = 60,
        half_life_days: float = 14.0,
    ) -> Dict[str, float]:
        """Return decay-weighted analyst feedback stats for adaptive trust/suppression."""
        days = max(7, int(lookback_days or 60))
        half_life = max(1.0, float(half_life_days or 14.0))
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")

        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT analyst_label, weight, created_at
            FROM false_positive_feedback
            WHERE fingerprint=? AND created_at > ?
            ORDER BY created_at ASC
            """,
            (fingerprint, cutoff),
        )
        rows = cur.fetchall()
        conn.close()

        false_w = 0.0
        true_w = 0.0
        neutral_w = 0.0
        now = datetime.now(timezone.utc)

        for label, weight, created_at in rows:
            raw_label = str(label or "").strip().lower()
            base_weight = max(0.05, float(weight or 1.0))
            try:
                created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
            except Exception:
                created = now

            age_days = max(0.0, (now - created).total_seconds() / 86400.0)
            decay = 0.5 ** (age_days / half_life)
            weighted = base_weight * decay

            if raw_label == "false_positive":
                false_w += weighted
            elif raw_label in {"true_positive", "malicious"}:
                true_w += weighted
            else:
                neutral_w += weighted

        denom = false_w + true_w + neutral_w + 0.5
        trust = max(0.0, min(1.0, false_w / denom))
        certainty = max(0.0, min(1.0, (false_w + true_w) / (false_w + true_w + neutral_w + 1.0)))
        margin = false_w - true_w

        return {
            "false_weight": round(false_w, 6),
            "true_weight": round(true_w, 6),
            "neutral_weight": round(neutral_w, 6),
            "trust_score": round(trust, 6),
            "confidence": round(certainty, 6),
            "margin": round(margin, 6),
            "lookback_days": float(days),
            "half_life_days": float(half_life),
            "samples": float(len(rows)),
        }

    def should_suppress_fingerprint(
        self,
        fingerprint: str,
        min_trust: float = 0.68,
        min_margin: float = 0.75,
        min_samples: int = 3,
    ) -> Dict[str, Any]:
        """Decide whether a fingerprint should be suppressed using decay-weighted trust."""
        stats = self.decayed_feedback_stats(fingerprint=fingerprint)
        trust = float(stats.get("trust_score", 0.0) or 0.0)
        margin = float(stats.get("margin", 0.0) or 0.0)
        samples = int(stats.get("samples", 0.0) or 0)

        suppress = (
            samples >= int(min_samples)
            and trust >= float(min_trust)
            and margin >= float(min_margin)
        )
        return {
            "suppress": bool(suppress),
            "trust_score": trust,
            "margin": margin,
            "samples": samples,
            "stats": stats,
            "policy": {
                "min_trust": float(min_trust),
                "min_margin": float(min_margin),
                "min_samples": int(min_samples),
            },
        }

    def append_immutable_audit(self, event_type: str, actor: str, target: str, details: Optional[Dict[str, Any]] = None) -> str:
        payload = json.dumps(details or {}, sort_keys=True)
        with self._lock:
            conn = self._connect()
            cur = conn.cursor()
            cur.execute("SELECT entry_hash FROM immutable_audit_log ORDER BY id DESC LIMIT 1")
            prev = (cur.fetchone() or [""])[0] or ""
            body = f"{event_type}|{actor}|{target}|{payload}|{prev}|{time.time()}"
            entry_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
            cur.execute(
                "INSERT INTO immutable_audit_log(event_type, actor, target, details, prev_hash, entry_hash) VALUES(?, ?, ?, ?, ?, ?)",
                (event_type, actor, target, payload, prev, entry_hash),
            )
            conn.commit()
            conn.close()
        return entry_hash

    def get_api_quality_snapshot(self, window_hours: int = 24) -> Dict[str, Dict[str, Any]]:
        """Return per-provider quality metrics for dashboard and policy decisions."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                api_name,
                COUNT(*) AS total_calls,
                SUM(CASE WHEN status='checked' THEN 1 ELSE 0 END) AS successes,
                SUM(CASE WHEN status IN ('error', 'exception') THEN 1 ELSE 0 END) AS failures,
                SUM(CASE WHEN status='queue_backpressure' THEN 1 ELSE 0 END) AS backpressure,
                SUM(CASE WHEN is_timeout=1 THEN 1 ELSE 0 END) AS timeouts,
                AVG(latency_ms) AS avg_latency_ms,
                MAX(created_at) AS last_seen
            FROM api_quality_metrics
            WHERE created_at > ?
            GROUP BY api_name
            """,
            (cutoff,),
        )
        rows = cur.fetchall()
        conn.close()

        snapshot: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            api_name = str(row[0] or "unknown")
            total = int(row[1] or 0)
            successes = int(row[2] or 0)
            failures = int(row[3] or 0)
            backpressure = int(row[4] or 0)
            timeouts = int(row[5] or 0)
            avg_latency = float(row[6] or 0.0)
            last_seen = row[7]
            circuit = self.get_circuit_state(api_name)
            snapshot[api_name] = {
                "total_calls": total,
                "successes": successes,
                "failures": failures,
                "backpressure_events": backpressure,
                "timeouts": timeouts,
                "avg_latency_ms": round(avg_latency, 2),
                "success_rate": round((successes / total), 4) if total else 0.0,
                "health_score": round(self.get_api_health_score(api_name, window_hours=window_hours), 4),
                "circuit": circuit,
                "last_seen": last_seen,
            }
        return snapshot

    def get_correlation_summary(self, minutes: int = 60) -> Dict[str, Any]:
        """Summarize recent correlation activity for attack-chain and recurrence views."""
        events = self.get_recent_events(minutes=minutes)
        by_type: Dict[str, int] = {}
        by_verdict: Dict[str, int] = {}
        pair_counts: Dict[str, int] = {}

        for event in events:
            e_type = str(event.get("type") or "unknown").lower()
            verdict = str(event.get("verdict") or "unknown").lower()
            by_type[e_type] = by_type.get(e_type, 0) + 1
            by_verdict[verdict] = by_verdict.get(verdict, 0) + 1

        # Relationship hints (phish->download->c2 style) in rolling window order.
        ordered = list(reversed(events))
        for idx in range(1, len(ordered)):
            prev_t = str(ordered[idx - 1].get("type") or "unknown").lower()
            cur_t = str(ordered[idx].get("type") or "unknown").lower()
            pair = f"{prev_t}->{cur_t}"
            pair_counts[pair] = pair_counts.get(pair, 0) + 1

        top_pairs = sorted(pair_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        return {
            "window_minutes": minutes,
            "total_events": len(events),
            "by_type": by_type,
            "by_verdict": by_verdict,
            "top_transitions": [{"chain": p, "count": c} for p, c in top_pairs],
        }

    def get_recent_audit_entries(self, limit: int = 100, event_type: Optional[str] = None) -> list[Dict[str, Any]]:
        """Return immutable audit entries for forensic and compliance surfaces."""
        conn = self._connect()
        cur = conn.cursor()
        if event_type:
            cur.execute(
                """
                SELECT id, event_type, actor, target, details, prev_hash, entry_hash, created_at
                FROM immutable_audit_log
                WHERE event_type = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (event_type, max(1, int(limit))),
            )
        else:
            cur.execute(
                """
                SELECT id, event_type, actor, target, details, prev_hash, entry_hash, created_at
                FROM immutable_audit_log
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(1, int(limit)),),
            )
        rows = cur.fetchall()
        conn.close()

        out = []
        for row in rows:
            try:
                details = json.loads(row[4] or "{}")
            except Exception:
                details = {"raw": row[4]}
            out.append(
                {
                    "id": int(row[0]),
                    "event_type": row[1],
                    "actor": row[2],
                    "target": row[3],
                    "details": details,
                    "prev_hash": row[5],
                    "entry_hash": row[6],
                    "created_at": row[7],
                }
            )
        return out

    @staticmethod
    def _detector_from_input_type(input_type: str) -> str:
        value = str(input_type or "").strip().lower()
        if value in {"ip", "network", "network_traffic"}:
            return "network"
        if value in {"file", "file_hash", "hash"}:
            return "file"
        if value in {"url", "domain", "browser"}:
            return "browser"
        if value in {"ids", "attack", "attack_event", "intrusion"}:
            return "ids"
        return "default"

    @staticmethod
    def _probability_from_verdict(verdict: str) -> float:
        value = str(verdict or "").strip().lower()
        if value in {"malicious", "critical", "threat"}:
            return 0.92
        if value in {"suspicious", "high", "medium"}:
            return 0.68
        if value in {"safe", "clean", "low"}:
            return 0.10
        return 0.50

    @staticmethod
    def _label_to_ground_truth(label: str) -> Optional[int]:
        value = str(label or "").strip().lower()
        if value in {"true_positive", "malicious"}:
            return 1
        if value == "false_positive":
            return 0
        return None

    def get_accuracy_metrics(self, lookback_days: int = 30) -> Dict[str, Any]:
        """Return Brier score, precision/recall by detector, and weekly false-positive trend."""
        days = max(7, int(lookback_days or 30))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT input_type, verdict, analyst_label, weight, created_at
            FROM false_positive_feedback
            WHERE created_at > ?
            ORDER BY created_at ASC
            """,
            (cutoff,),
        )
        feedback_rows = cur.fetchall()

        cur.execute(
            """
            SELECT strftime('%Y-%W', created_at) AS week_bucket,
                   SUM(CASE WHEN analyst_label='false_positive' THEN 1 ELSE 0 END) AS fp_count,
                   COUNT(*) AS total_count
            FROM false_positive_feedback
            WHERE created_at > ?
            GROUP BY week_bucket
            ORDER BY week_bucket ASC
            """,
            (cutoff,),
        )
        trend_rows = cur.fetchall()
        conn.close()

        detector_stats: Dict[str, Dict[str, float]] = {}
        brier_sum = 0.0
        brier_weight_sum = 0.0

        for input_type, verdict, analyst_label, weight, _created_at in feedback_rows:
            detector = self._detector_from_input_type(str(input_type or "default"))
            stats = detector_stats.setdefault(
                detector,
                {
                    "tp": 0.0,
                    "fp": 0.0,
                    "fn": 0.0,
                    "tn": 0.0,
                    "support": 0.0,
                    "false_positive": 0.0,
                },
            )
            w = max(0.1, float(weight or 1.0))
            y = self._label_to_ground_truth(str(analyst_label or ""))
            p = self._probability_from_verdict(str(verdict or ""))
            predicted_positive = 1 if p >= 0.50 else 0

            if y is not None:
                stats["support"] += w
                brier_sum += ((p - float(y)) ** 2) * w
                brier_weight_sum += w
                if predicted_positive == 1 and y == 1:
                    stats["tp"] += w
                elif predicted_positive == 1 and y == 0:
                    stats["fp"] += w
                elif predicted_positive == 0 and y == 1:
                    stats["fn"] += w
                else:
                    stats["tn"] += w

            if str(analyst_label or "").strip().lower() == "false_positive":
                stats["false_positive"] += w

        by_detector: Dict[str, Dict[str, Any]] = {}
        for detector, s in detector_stats.items():
            tp = float(s["tp"])
            fp = float(s["fp"])
            fn = float(s["fn"])
            support = float(s["support"])
            precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            fp_rate = (float(s["false_positive"]) / support) if support > 0 else 0.0
            by_detector[detector] = {
                "samples": round(support, 2),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "false_positive_rate": round(fp_rate, 4),
            }

        trend = []
        for week_bucket, fp_count, total_count in trend_rows:
            total = int(total_count or 0)
            fp = int(fp_count or 0)
            trend.append(
                {
                    "week": str(week_bucket or "unknown"),
                    "false_positive": fp,
                    "total": total,
                    "false_positive_rate": round((fp / total), 4) if total else 0.0,
                }
            )

        return {
            "lookback_days": days,
            "brier_score": round((brier_sum / brier_weight_sum), 6) if brier_weight_sum > 0 else None,
            "samples": round(brier_weight_sum, 2),
            "by_detector": by_detector,
            "false_positive_trend": trend,
        }

    def build_adaptive_threshold_recommendations(
        self,
        current_profiles: Dict[str, Dict[str, Any]],
        lookback_days: int = 28,
        min_samples: int = 10,
    ) -> Dict[str, Any]:
        """Learn detector-specific threshold recommendations from analyst feedback."""
        metrics = self.get_accuracy_metrics(lookback_days=lookback_days)
        by_detector = metrics.get("by_detector", {}) or {}

        updated_profiles: Dict[str, Dict[str, Any]] = {}
        diagnostics: Dict[str, Dict[str, Any]] = {}

        for detector, profile in (current_profiles or {}).items():
            if detector == "default":
                continue
            baseline = dict(profile or {})
            stats = by_detector.get(detector, {})
            samples = float(stats.get("samples", 0.0) or 0.0)
            fp_rate = float(stats.get("false_positive_rate", 0.0) or 0.0)
            precision = float(stats.get("precision", 0.0) or 0.0)
            recall = float(stats.get("recall", 0.0) or 0.0)

            crit = float(baseline.get("critical", 0.94) or 0.94)
            high = float(baseline.get("high", 0.84) or 0.84)
            med = float(baseline.get("medium", 0.62) or 0.62)
            single = float(baseline.get("single_source_auto_high_min", 0.94) or 0.94)

            adjustment = 0.0
            if samples >= float(min_samples):
                # Raise thresholds when false positives increase.
                if fp_rate > 0.35:
                    adjustment += 0.04
                elif fp_rate > 0.25:
                    adjustment += 0.02

                # Lower thresholds slightly if precision is strong but recall is weak.
                if precision >= 0.8 and recall < 0.6:
                    adjustment -= 0.02

            crit_n = max(0.88, min(0.99, crit + adjustment))
            high_n = max(0.74, min(crit_n - 0.04, high + adjustment))
            med_n = max(0.50, min(high_n - 0.10, med + (adjustment * 0.5)))
            single_n = max(high_n + 0.06, min(0.995, single + max(0.0, adjustment)))

            updated_profiles[detector] = {
                "critical": round(crit_n, 4),
                "high": round(high_n, 4),
                "medium": round(med_n, 4),
                "single_source_auto_high_min": round(single_n, 4),
            }
            diagnostics[detector] = {
                "samples": round(samples, 2),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "false_positive_rate": round(fp_rate, 4),
                "adjustment": round(adjustment, 4),
            }

        return {
            "lookback_days": lookback_days,
            "min_samples": min_samples,
            "metrics": metrics,
            "updated_profiles": updated_profiles,
            "diagnostics": diagnostics,
        }


security_telemetry = EnhancedSecurityTelemetryStore()
