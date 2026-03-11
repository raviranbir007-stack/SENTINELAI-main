"""
SENTINEL-AI Automated Security System
Fully automated threat detection with continuous monitoring
No manual URL/IP/domain copying required
"""

import asyncio
import json
import logging
import platform
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests

# Import our new components
sys.path.insert(0, str(Path(__file__).parent))
from scanner.traffic_monitor import AutomaticTrafficMonitor, NetworkArtifact
from scanner.activity_logger import ActivityLogger
from scanner.intrusion_detector import IntrusionDetector

# Configuration
CONFIG_FILE = Path("config.ini")
LOG_FILE = Path("sentinel_automated.log")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger("SentinelAutomated")


class SentinelAutomatedSystem:
    """
    Fully Automated SENTINEL-AI Security System
    
    Features:
    - Automatic network traffic monitoring
    - Real-time artifact extraction (URLs, IPs, domains)
    - Continuous threat scanning with multi-API corroboration
    - No manual input required
    - Manual re-analysis option available
    """
    
    def __init__(self, config_path: Path = CONFIG_FILE):
        self.config = self._load_config(config_path)
        self.server_url = self.config.get("server", {}).get("url", "http://localhost:5000")
        self.api_key = self.config.get("server", {}).get("api_key", "")
        
        # Initialize monitoring components
        self.traffic_monitor = None
        self.activity_logger = None
        self.intrusion_detector = None
        
        # State
        self.running = False
        self.scan_tasks = []
        
        # Statistics
        self.stats = {
            'start_time': None,
            'scans_performed': 0,
            'threats_detected': 0,
            'artifacts_extracted': 0,
            'auto_scans': 0,
            'manual_scans': 0
        }
        
        logger.info("🤖 SENTINEL-AI Automated System initialized")
    
    def _load_config(self, config_path: Path) -> Dict:
        """Load configuration from file"""
        try:
            if config_path.exists():
                import configparser
                config = configparser.ConfigParser()
                config.read(config_path)
                return {section: dict(config.items(section)) for section in config.sections()}
            else:
                logger.warning(f"Config file not found: {config_path}, using defaults")
                return {
                    'server': {'url': 'http://localhost:5000', 'api_key': ''},
                    'monitoring': {
                        'scan_interval': '60',
                        'batch_size': '10',
                        'enable_traffic_capture': 'true'
                    }
                }
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication"""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers
    
    async def scan_artifact(self, artifact: NetworkArtifact) -> Dict:
        """
        Send artifact to server for threat analysis
        
        Args:
            artifact: Network artifact to scan
        
        Returns:
            Scan result from server
        """
        try:
            logger.info(f"🔍 Scanning {artifact.type}: {artifact.value}")
            
            # Prepare request
            url = f"{self.server_url}/api/scan"
            payload = {
                "input": artifact.value,
                "type": artifact.type,
                "metadata": {
                    **artifact.metadata,
                    "source": artifact.source,
                    "timestamp": artifact.timestamp.isoformat(),
                    "automated": True
                }
            }
            
            # Send to server
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Update statistics
                self.stats['scans_performed'] += 1
                self.stats['auto_scans'] += 1
                
                # Check if threat detected
                verdict = result.get('verdict', 'unknown')
                if verdict in ['malicious', 'suspicious', 'critical']:
                    self.stats['threats_detected'] += 1
                    logger.warning(
                        f"⚠️ THREAT DETECTED: {artifact.type} - {artifact.value} "
                        f"[{verdict.upper()}]"
                    )
                    
                    # Handle threat
                    await self._handle_threat_detection(artifact, result)
                else:
                    logger.info(f"✅ Clean: {artifact.type} - {artifact.value}")
                
                return result
            else:
                logger.error(f"Server returned error: {response.status_code}")
                return {
                    'error': f"Server error: {response.status_code}",
                    'verdict': 'unknown'
                }
                
        except requests.exceptions.Timeout:
            logger.error(f"Scan timeout for {artifact.value}")
            return {'error': 'Timeout', 'verdict': 'unknown'}
        except Exception as e:
            logger.error(f"Error scanning {artifact.value}: {e}")
            return {'error': str(e), 'verdict': 'unknown'}
    
    async def _handle_threat_detection(self, artifact: NetworkArtifact, scan_result: Dict):
        """
        Handle detected threats with appropriate actions
        
        Args:
            artifact: The artifact that was identified as a threat
            scan_result: Full scan result from server
        """
        verdict = scan_result.get('verdict', 'unknown')
        confidence = scan_result.get('confidence', 0.0)
        
        # Get corroboration data
        corroboration = scan_result.get('corroboration_analysis', {})
        source_count = corroboration.get('corroboration', {}).get('source_count', 0)
        recommendations = scan_result.get('recommendations', [])
        flags = scan_result.get('flags', {})
        
        logger.warning("=" * 70)
        logger.warning(f"🚨 THREAT ALERT")
        logger.warning("=" * 70)
        logger.warning(f"Type: {artifact.type}")
        logger.warning(f"Value: {artifact.value}")
        logger.warning(f"Verdict: {verdict.upper()}")
        logger.warning(f"Confidence: {confidence:.1%}")
        logger.warning(f"Corroboration: {source_count} sources")
        logger.warning(f"Source: {artifact.source}")
        
        # Display corroboration details
        if corroboration:
            corr_level = corroboration.get('corroboration', {}).get('level', 'unknown')
            logger.warning(f"Corroboration Level: {corr_level.upper()}")
            
            sources = corroboration.get('corroboration', {}).get('sources', [])
            if sources:
                logger.warning(f"Confirming Sources: {', '.join(sources)}")
        
        # Display flags
        if flags.get('single_source_only'):
            logger.warning("⚠️ WARNING: Single source detection - High false positive risk")
        if flags.get('novel_threat_indicator'):
            logger.warning("🔬 NOVEL THREAT: Potential zero-day indicator")
        if flags.get('meets_incident_threshold'):
            logger.warning("🚨 INCIDENT RESPONSE THRESHOLD MET")
        
        # Display recommendations
        if recommendations:
            logger.warning("\nRecommended Actions:")
            for rec in recommendations:
                logger.warning(f"  • {rec}")
        
        logger.warning("=" * 70)
        
        # Log to file for incident tracking
        self._log_threat_to_file(artifact, scan_result)
    
    def _log_threat_to_file(self, artifact: NetworkArtifact, scan_result: Dict):
        """Log threat details to file for incident tracking"""
        try:
            threat_log = Path("threats_detected.json")
            
            # Load existing threats
            if threat_log.exists():
                with open(threat_log, 'r') as f:
                    threats = json.load(f)
            else:
                threats = []
            
            # Add new threat
            threat_record = {
                'timestamp': datetime.utcnow().isoformat(),
                'artifact': artifact.to_dict(),
                'scan_result': {
                    'verdict': scan_result.get('verdict'),
                    'confidence': scan_result.get('confidence'),
                    'summary': scan_result.get('summary'),
                    'corroboration': scan_result.get('corroboration_analysis', {}).get('corroboration', {}),
                    'recommendations': scan_result.get('recommendations', []),
                    'flags': scan_result.get('flags', {})
                }
            }
            threats.append(threat_record)
            
            # Save
            with open(threat_log, 'w') as f:
                json.dump(threats, f, indent=2)
            
            logger.info(f"✅ Threat logged to {threat_log}")
            
        except Exception as e:
            logger.error(f"Error logging threat: {e}")
    
    async def manual_scan(self, value: str, artifact_type: str = None) -> Dict:
        """
        Manually trigger a scan (for re-analysis)
        
        Args:
            value: URL, IP, domain, or hash to scan
            artifact_type: Optional type hint ('ip', 'url', 'domain', 'hash')
        
        Returns:
            Scan result
        """
        logger.info(f"🔬 Manual scan requested: {value}")
        
        # Create artifact
        artifact = NetworkArtifact(
            artifact_type=artifact_type or 'unknown',
            value=value,
            source='manual',
            metadata={'manual_scan': True, 'requested_at': datetime.utcnow().isoformat()}
        )
        
        # Scan
        result = await self.scan_artifact(artifact)
        
        # Update stats
        self.stats['manual_scans'] += 1
        
        return result
    
    async def start_automated_monitoring(self):
        """Start all automated monitoring components"""
        if self.running:
            logger.warning("Automated monitoring already running")
            return
        
        self.running = True
        self.stats['start_time'] = datetime.utcnow()
        
        logger.info("=" * 70)
        logger.info("🚀 STARTING SENTINEL-AI AUTOMATED SECURITY SYSTEM")
        logger.info("=" * 70)
        logger.info(f"Server: {self.server_url}")
        logger.info(f"Platform: {platform.system()} {platform.release()}")
        logger.info(f"Mode: Fully Automated")
        logger.info("=" * 70)
        
        # Initialize traffic monitor
        monitoring_config = {
            'scan_interval': int(self.config.get('monitoring', {}).get('scan_interval', 60)),
            'batch_size': int(self.config.get('monitoring', {}).get('batch_size', 10))
        }
        
        self.traffic_monitor = AutomaticTrafficMonitor(
            scan_callback=self.scan_artifact,
            config=monitoring_config
        )
        
        # Start traffic monitoring
        self.traffic_monitor.start()
        logger.info("✅ Traffic monitor started")
        
        # Initialize activity logger
        self.activity_logger = ActivityLogger(callback=self._activity_callback)
        self.activity_logger.start()
        logger.info("✅ Activity logger started")
        
        # Initialize intrusion detector
        self.intrusion_detector = IntrusionDetector(callback=self._intrusion_callback)
        self.intrusion_detector.start()
        logger.info("✅ Intrusion detector started")
        
        # Start scan loop
        logger.info("🔍 Starting automated scanning loop...")
        
        # Create tasks
        tasks = [
            asyncio.create_task(self.traffic_monitor.start_scan_loop()),
            asyncio.create_task(self._status_report_loop()),
        ]
        
        self.scan_tasks = tasks
        
        # Wait for tasks
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Monitoring tasks cancelled")
    
    def _activity_callback(self, activity_data: Dict):
        """Callback for activity logger events"""
        # Extract network artifacts from activity
        if activity_data.get('type') == 'website':
            url = activity_data.get('url')
            if url:
                self.traffic_monitor.manual_scan(url, 'url')
    
    def _intrusion_callback(self, intrusion_data: Dict):
        """Callback for intrusion detector events"""
        # Extract IPs from intrusion attempts
        ip = intrusion_data.get('source_ip')
        if ip:
            self.traffic_monitor.manual_scan(ip, 'ip')
    
    async def _status_report_loop(self):
        """Periodically report system status"""
        while self.running:
            await asyncio.sleep(300)  # Every 5 minutes
            self._print_status()
    
    def _print_status(self):
        """Print current system status"""
        # Get traffic monitor stats
        traffic_stats = self.traffic_monitor.get_statistics() if self.traffic_monitor else {}
        
        # Calculate uptime
        if self.stats['start_time']:
            uptime = datetime.utcnow() - self.stats['start_time']
            uptime_str = str(uptime).split('.')[0]  # Remove microseconds
        else:
            uptime_str = "N/A"
        
        logger.info("=" * 70)
        logger.info("📊 SENTINEL-AI AUTOMATED SYSTEM STATUS")
        logger.info("=" * 70)
        logger.info(f"Uptime: {uptime_str}")
        logger.info(f"Artifacts Extracted: {traffic_stats.get('total_artifacts', 0)}")
        logger.info(f"  - Domains: {traffic_stats.get('domains_extracted', 0)}")
        logger.info(f"  - URLs: {traffic_stats.get('urls_extracted', 0)}")
        logger.info(f"  - IPs: {traffic_stats.get('ips_extracted', 0)}")
        logger.info(f"Scans Performed: {self.stats['scans_performed']}")
        logger.info(f"  - Automated: {self.stats['auto_scans']}")
        logger.info(f"  - Manual: {self.stats['manual_scans']}")
        logger.info(f"Threats Detected: {self.stats['threats_detected']}")
        logger.info(f"Pending Scans: {traffic_stats.get('queue_size', 0)}")
        logger.info("=" * 70)
    
    def stop(self):
        """Stop all monitoring"""
        logger.info("🛑 Stopping SENTINEL-AI Automated System...")
        
        self.running = False
        
        # Stop components
        if self.traffic_monitor:
            self.traffic_monitor.stop()
        
        if self.activity_logger:
            self.activity_logger.stop()
        
        if self.intrusion_detector:
            self.intrusion_detector.stop()
        
        # Cancel tasks
        for task in self.scan_tasks:
            task.cancel()
        
        # Final status
        self._print_status()
        
        logger.info("✅ SENTINEL-AI Automated System stopped")


async def main():
    """Main entry point"""
    import signal
    
    # Create system
    system = SentinelAutomatedSystem()
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        logger.info("\n🛑 Shutdown signal received")
        system.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start system
    try:
        await system.start_automated_monitoring()
    except KeyboardInterrupt:
        logger.info("\n🛑 Keyboard interrupt received")
        system.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        system.stop()


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                  SENTINEL-AI AUTOMATED SYSTEM                    ║
║              Fully Automated Threat Detection                    ║
║          No Manual URL/IP/Domain Copying Required                ║
╚══════════════════════════════════════════════════════════════════╝

Features:
  ✓ Automatic network traffic monitoring
  ✓ Real-time artifact extraction
  ✓ Continuous threat scanning
  ✓ Multi-API corroboration
  ✓ Manual re-analysis option

Starting...
""")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n✅ Shutdown complete")
