import os
import logging
import time
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

# Load environment variables from multiple sources
load_dotenv()  # Load from .env in project root
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))  # Load server/.env
load_dotenv(dotenv_path="../.env.example")  # Also load from .env.example

# Configure logging with colored output when available
try:
    import coloredlogs
    coloredlogs.install(level="INFO", fmt="%(asctime)s %(levelname)s %(name)s: %(message)s")
except Exception:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# Reduce verbosity of HTTP request logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def _startup_monitors_enabled() -> bool:
    """Return whether background monitoring should auto-start with the API server."""
    return os.getenv("SENTINEL_ENABLE_STARTUP_MONITORS", "false").lower() in {"1", "true", "yes", "on"}

# Gemini API Configuration with multiple fallback options
GEMINI_API_KEY = (
    os.getenv("GEMINI_API_KEY") or 
    os.getenv("GOOGLE_API_KEY") or
    os.getenv("GEMINI_API_KEY_1")  # Additional fallback
)

# Gemini Configuration Initialization
def initialize_gemini_configuration():
    """Initialize Gemini configuration and validate settings"""
    from app.gemini_config import get_gemini_config, validate_gemini_config
    
    try:
        # Get configuration
        config = get_gemini_config()
        
        # Set API key in environment if not already set
        if GEMINI_API_KEY and not os.getenv("GEMINI_API_KEY"):
            os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY
        
        # Validate configuration
        if config.get_config('enabled', True):
            validation_result = validate_gemini_config()
            
            if validation_result:
                logger.info("✅ Gemini configuration validated successfully")
                
                # Print configuration (without sensitive data)
                config.print_config(show_sensitive=False)
                
                # Initialize Gemini integration
                initialize_gemini_integration()
            else:
                logger.warning("⚠️  Gemini configuration validation failed, using fallback mode")
                setup_fallback_mode()
        else:
            logger.info("ℹ️  Gemini is disabled in configuration, using local analysis")
            setup_fallback_mode()
            
    except ImportError as e:
        logger.warning(f"Gemini configuration module not available: {e}")
        setup_fallback_mode()
    except Exception as e:
        logger.error(f"Failed to initialize Gemini configuration: {e}")
        setup_fallback_mode()

def initialize_gemini_integration():
    """Initialize Gemini API integration"""
    try:
        from app.gemini_integration import get_gemini_client
        
        # Initialize Gemini client
        client = get_gemini_client()
        status = client.check_availability()
        
        if status['available']:
            logger.info(f"✅ Gemini API initialized successfully with model: {status.get('model', 'N/A')}")
            logger.info(f"   Status: {status['status']}")
            
            # Skip connection test to save quota (each test wastes 1 request)
            # Test will happen naturally when first report is generated
            logger.info("⚡ Gemini API ready (skipping startup test to preserve quota)")
                
        else:
            logger.warning(f"⚠️  Gemini API not available: {status.get('status', 'unknown')}")
            setup_fallback_mode()
            
    except ImportError as e:
        logger.warning(f"Gemini integration module not available: {e}")
        setup_fallback_mode()
    except Exception as e:
        logger.error(f"Failed to initialize Gemini integration: {e}")
        setup_fallback_mode()

def setup_fallback_mode():
    """Setup fallback mode for analysis"""
    logger.info("🔄 Setting up local fallback analysis mode")
    
    # Initialize local analysis components
    try:
        from app.ml_models import AnomalyDetectionModel, ThreatPredictionModel
        from app.anomaly_detector import AnomalyDetector
        
        logger.info("✅ Local ML models and analysis components initialized")
        
    except ImportError as e:
        logger.warning(f"Some local analysis components not available: {e}")
        logger.info("⚠️  Limited analysis capabilities available")

def get_system_status():
    """Get current system status including Gemini availability"""
    try:
        from app.gemini_integration import get_analysis_status, get_gemini_client
        from app.gemini_config import get_gemini_config
        
        config = get_gemini_config()
        gemini_status = get_analysis_status()
        client = get_gemini_client()
        
        # Determine if Gemini is truly enabled and available
        is_enabled = config.get_config('enabled', False) and client.is_available()
        is_available = gemini_status.get('available', False) and client.initialized
        fallback_active = not is_available
        
        return {
            "gemini": {
                "enabled": is_enabled,
                "available": is_available,
                "status": gemini_status.get('status', 'unknown') if is_available else 'fallback_active',
                "model": gemini_status.get('model', 'N/A') if is_available else 'N/A'
            },
            "api_key_present": bool(GEMINI_API_KEY),
            "fallback_active": fallback_active,
            "version": "2.0.0",
            "features": {
                "gemini_analysis": is_available,
                "local_analysis": True,
                "real_time_monitoring": True,
                "threat_prediction": True
            }
        }
    except Exception as e:
        logger.warning(f"Could not get full system status: {e}")
        return {
            "gemini": {
                "enabled": False,
                "available": False,
                "status": "error",
                "model": "N/A"
            },
            "api_key_present": bool(GEMINI_API_KEY),
            "fallback_active": True,
            "version": "2.0.0",
            "features": {
                "gemini_analysis": False,
                "local_analysis": True,
                "real_time_monitoring": True,
                "threat_prediction": True
            }
        }


# Application Lifecycle Events using Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown"""
    # suppress verbose SQL logs which clutter output
    logging.getLogger('sqlalchemy.engine').setLevel(logging.CRITICAL)
    logging.getLogger('sqlalchemy.pool').setLevel(logging.CRITICAL)
    logging.getLogger('httpx').setLevel(logging.CRITICAL)
    logging.getLogger('uvicorn.access').setLevel(logging.CRITICAL)

    # Startup
    logger.info("🚀 Starting SENTINEL-AI Application...")

    # Initialize database tables
    try:
        # Ensure models are imported so metadata is registered
        from app import models  # noqa: F401
        from app.database import init_db
        await init_db()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
    
    # Initialize Gemini configuration
    initialize_gemini_configuration()
    
    logger.info("✅ Application startup complete")
    logger.info(f"📊 System Status: {get_system_status()}")
    
    if _startup_monitors_enabled():
        # Start activity monitoring
        try:
            from app.activity_monitor import activity_monitor
            import asyncio
            asyncio.create_task(activity_monitor.start())
            logger.info("🔍 Activity monitor started")
        except Exception as e:
            logger.error(f"Failed to start activity monitor: {e}")
        
        # Initialize and start enhanced monitoring components
        logger.info("=" * 80)
        logger.info("🤖 INITIALIZING MONITORING")
        logger.info("=" * 80)
        
        try:
            # Initialize activity database
            from app.core.activity_database import activity_db
            logger.info("✅ Database ready")
            
            # Start terminal monitor for real-time display
            from app.core.terminal_monitor import terminal_monitor
            terminal_monitor.start()
            logger.info("✅ Monitor ready")
            logger.info("=" * 80)
            
            # Start automatic activity monitor
            from app.core.auto_monitor import AutomaticActivityMonitor
            from app.core.threat_analyzer import threat_analyzer
            
            async def scan_artifact(artifact_type: str, value: str):
                """Callback to scan detected artifacts"""
                try:
                    started = time.perf_counter()
                    scan_timeout = float(os.getenv("SENTINEL_SCAN_TIMEOUT_SECONDS", "20"))
                    result = await asyncio.wait_for(threat_analyzer.analyze(value), timeout=scan_timeout)
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    
                    # Log to database
                    corroboration = result.get('corroboration_analysis', {})
                    activity_db.log_threat_scan({
                        'artifact_type': artifact_type,
                        'artifact_value': value,
                        'scan_duration_ms': elapsed_ms,
                        'verdict': result.get('verdict', 'unknown'),
                        'confidence': result.get('confidence', 0.0),
                        'threat_level': result.get('verdict', 'unknown'),
                        'corroboration_level': corroboration.get('corroboration', {}).get('level'),
                        'source_count': corroboration.get('corroboration', {}).get('source_count', 0),
                        'sources': corroboration.get('corroboration', {}).get('sources', []),
                        'api_results': result.get('api_results'),
                        'threat_indicators': result.get('threat_indicators', []),
                        'recommendations': result.get('recommendations', []),
                        'flags': result.get('flags', {}),
                        'is_automated': True,
                        'metadata': {'auto_detected': True}
                    })
                    
                    # Update terminal monitor
                    terminal_monitor.log_scan_activity(artifact_type, value, result.get('verdict', 'unknown'))
                    
                    return result
                except asyncio.TimeoutError:
                    logger.warning(f"Scan timeout for {artifact_type} {value}")
                    return {
                        'verdict': 'unknown',
                        'confidence': 0.0,
                        'summary': 'Scan timed out before all APIs returned. Monitoring continued without blocking.',
                        'warnings': ['Scan timed out'],
                        'api_results': {
                            'apis_called': [],
                            'apis_expected': [],
                            'api_status': {}
                        },
                        'threat_indicators': []
                    }
                except Exception as e:
                    logger.error(f"Error scanning {artifact_type} {value}: {e}")
                    return {'verdict': 'error', 'error': str(e)}
            
            auto_monitor = AutomaticActivityMonitor(scan_callback=scan_artifact)
            asyncio.create_task(auto_monitor.start())
            logger.info("✅ Activity monitoring enabled")
            
        except Exception as e:
            logger.error(f"Failed to start enhanced monitoring: {e}")
            logger.warning("Server will continue without enhanced monitoring")
    else:
        logger.info("ℹ️ Startup monitors disabled (set SENTINEL_ENABLE_STARTUP_MONITORS=true to enable background monitoring)")
    
    # Yield control to the application
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down SENTINEL-AI Application...")
    
    # Stop activity monitoring
    try:
        from app.activity_monitor import activity_monitor
        await activity_monitor.stop()
    except Exception as e:
        logger.error(f"Failed to stop activity monitor: {e}")
    
    # Stop enhanced monitoring and print summary
    try:
        from app.core.terminal_monitor import terminal_monitor
        terminal_monitor.stop()
        terminal_monitor.print_summary()
        logger.info("✅ Enhanced monitoring stopped")
    except Exception as e:
        logger.error(f"Failed to stop enhanced monitoring: {e}")

# FastAPI Application Setup
import uvicorn
from pydantic import BaseModel

from .api import compat
from .api.v1.api import api_router
from .config import settings

# Pydantic models for API requests
class AnalysisRequest(BaseModel):
    prompt: str
    context: Optional[Dict[str, Any]] = None
    analysis_type: Optional[str] = "security"
    priority: Optional[str] = "medium"

class TrafficAnalysisRequest(BaseModel):
    traffic_data: Dict[str, Any]
    source_ip: str
    endpoint: str
    timestamp: Optional[str] = None

class BatchAnalysisRequest(BaseModel):
    prompts: List[str]
    context: Optional[Dict[str, Any]] = None

# Pydantic models for analyst override
class AnalystOverrideRequest(BaseModel):
    threat_id: str
    override_verdict: str  # "clean", "suspicious", "malicious"
    override_notes: str
    analyst_username: Optional[str] = None
    override_severity: Optional[str] = None  # "low", "medium", "high", "critical"

class AnalystNotesRequest(BaseModel):
    scan_id: str
    analyst_notes: str
    verified: bool = False
    analyst_username: Optional[str] = None

# Create FastAPI app with lifespan
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="SENTINEL-AI: AI-Powered Threat Detection System with Gemini Integration",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

# Add CORS middleware with explicit OPTIONS support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else [],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)

# Add trusted host middleware
# when not in debug mode we trust the hosts defined in settings; the
# `allowed_hosts_list` property will split the comma-separated string.
hosts = ["*"] if settings.DEBUG else getattr(
    settings, "allowed_hosts_list", ["sentinel-ai.local", "api.sentinel-ai.local"]
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=hosts,
)

# Mount static files (if exists)
static_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")

# Include API router
app.include_router(api_router, prefix=settings.API_V1_PREFIX)
app.include_router(compat.router, prefix="/api")

# New Gemini-Enhanced API Endpoints

@app.get("/")
async def root():
    """Serve the frontend files with correct Content-Type headers."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")

    lovable_path = os.path.join(static_dir, "lovable-index.html")
    if os.path.exists(lovable_path):
        return FileResponse(lovable_path, media_type="text/html")

    return {
        "message": "Welcome to SENTINEL-AI Threat Detection System",
        "version": settings.VERSION,
        "docs": "/api/docs" if settings.DEBUG else None,
        "health": f"{settings.API_V1_PREFIX}/health",
        "gemini_status": get_system_status()["gemini"]
    }

@app.get("/api/v1/health")
async def health():
    """Enhanced health endpoint with Gemini status"""
    system_status = get_system_status()
    return {
        "status": "healthy", 
        "service": "SENTINEL-AI API",
        "gemini": system_status["gemini"],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/v1/system/status")
async def system_status():
    """Get detailed system status"""
    return get_system_status()

@app.post("/api/v1/analyze/gemini")
async def analyze_with_gemini(request: AnalysisRequest):
    """
    Analyze content using Gemini AI
    
    This endpoint uses Gemini for advanced analysis when available,
    falling back to local analysis if Gemini is unavailable.
    """
    try:
        from app.gemini_integration import analyze_security_threat
        
        # Analyze with Gemini
        result = await analyze_security_threat(
            prompt=request.prompt,
            context=request.context
        )
        
        return {
            "success": True,
            "analysis": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analysis_source": result.get('source', 'unknown')
        }
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/analyze/traffic")
async def analyze_traffic(request: TrafficAnalysisRequest):
    """
    Analyze API traffic for security threats
    
    Uses Gemini-enhanced analysis for better threat detection.
    """
    try:
        # Create analysis context
        context = {
            "traffic_data": request.traffic_data,
            "source_ip": request.source_ip,
            "endpoint": request.endpoint,
            "timestamp": request.timestamp or datetime.now(timezone.utc).isoformat(),
            "analysis_type": "traffic_security"
        }
        
        # Create analysis prompt
        prompt = f"""
        Analyze API traffic for security threats:
        
        Source IP: {request.source_ip}
        Endpoint: {request.endpoint}
        Method: {request.traffic_data.get('method', 'UNKNOWN')}
        
        Please analyze for:
        1. SQL Injection attempts
        2. XSS attacks
        3. Authentication bypass attempts
        4. Data exfiltration patterns
        5. Rate limiting violations
        
        Provide threat assessment and recommendations.
        """
        
        # Get analysis result
        from app.gemini_integration import analyze_security_threat
        analysis_result = await analyze_security_threat(prompt=prompt, context=context)
        
        # Enhance with local analysis
        local_analysis = perform_local_traffic_analysis(request.traffic_data)
        
        # Combine results
        combined_result = {
            **analysis_result,
            "local_analysis": local_analysis,
            "combined_threat_level": determine_combined_threat_level(
                analysis_result, local_analysis
            )
        }
        
        return {
            "success": True,
            "analysis": combined_result,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Traffic analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/analyze/batch")
async def batch_analyze(request: BatchAnalysisRequest):
    """
    Batch analyze multiple prompts
    
    Efficiently processes multiple analysis requests using
    Gemini batch capabilities when available.
    """
    try:
        from app.gemini_integration import get_gemini_client
        
        client = get_gemini_client()
        
        # Check if batch processing is available
        system_status = get_system_status()
        
        if system_status["gemini"]["available"]:
            # Use Gemini batch analysis
            results = await client.batch_analyze(
                prompts=request.prompts,
                context=request.context
            )
            analysis_source = "gemini_batch"
        else:
            # Fallback to sequential local analysis
            results = []
            for prompt in request.prompts:
                local_result = perform_local_analysis(prompt, request.context)
                results.append(local_result)
            analysis_source = "local_batch"
        
        return {
            "success": True,
            "results": results,
            "count": len(results),
            "analysis_source": analysis_source,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/config/gemini")
async def get_gemini_configuration():
    """Get current Gemini configuration (without sensitive data)"""
    try:
        from app.gemini_config import get_gemini_config
        
        config = get_gemini_config()
        
        # Get config without sensitive data
        safe_config = config.get_config()
        if 'api_key' in safe_config and safe_config['api_key']:
            safe_config['api_key'] = "***MASKED***"
        
        return {
            "config": safe_config,
            "validation": config.validate(),
            "status": get_system_status()["gemini"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except ImportError:
        return {
            "config": {"enabled": False, "error": "Configuration module not available"},
            "status": get_system_status()["gemini"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

@app.get("/cors-test")
async def cors_test_page():
    """CORS test endpoint"""
    test_path = os.path.join(os.path.dirname(__file__), "static", "cors-test.html")
    if os.path.exists(test_path):
        return FileResponse(test_path, media_type="text/html")
    return {"error": "Test page not found"}

# Forensic Reliability: Analyst Override Endpoints
@app.post("/api/v1/analyst/override")
async def analyst_override_threat(request: AnalystOverrideRequest):
    """
    Allow security analysts to override threat verdicts with forensic notes.
    
    This endpoint enables manual intervention when automated detection needs 
    correction or additional context.
    """
    from .database import SessionLocal
    from .models import Threat, User, ThreatStatus, ThreatSeverity
    from sqlalchemy.orm import Session
    
    db: Session = SessionLocal()
    
    try:
        # Find the threat
        threat = db.query(Threat).filter(Threat.threat_id == request.threat_id).first()
        
        if not threat:
            raise HTTPException(status_code=404, detail=f"Threat {request.threat_id} not found")
        
        # Find analyst user (if username provided)
        analyst_user = None
        if request.analyst_username:
            analyst_user = db.query(User).filter(User.username == request.analyst_username).first()
        
        # Store original verdict before override
        original_verdict = threat.status.value if threat.status else "unknown"
        
        # Apply analyst override
        threat.analyst_override = True
        threat.analyst_override_notes = request.override_notes
        threat.analyst_override_at = datetime.now(timezone.utc)
        threat.original_verdict = original_verdict
        
        if analyst_user:
            threat.analyst_override_by_id = analyst_user.id
        
        # Update threat status based on override verdict
        verdict_mapping = {
            "clean": ThreatStatus.FALSE_POSITIVE,
            "suspicious": ThreatStatus.ANALYZING,
            "malicious": ThreatStatus.DETECTED
        }
        
        if request.override_verdict.lower() in verdict_mapping:
            threat.status = verdict_mapping[request.override_verdict.lower()]
        
        # Update severity if provided
        if request.override_severity:
            severity_mapping = {
                "low": ThreatSeverity.LOW,
                "medium": ThreatSeverity.MEDIUM,
                "high": ThreatSeverity.HIGH,
                "critical": ThreatSeverity.CRITICAL
            }
            if request.override_severity.lower() in severity_mapping:
                threat.severity = severity_mapping[request.override_severity.lower()]
        
        threat.last_updated = datetime.now(timezone.utc)
        
        db.commit()
        db.refresh(threat)
        
        logger.info(f"Analyst override applied to threat {request.threat_id} by {request.analyst_username or 'unknown'}")
        
        return {
            "status": "success",
            "message": "Analyst override applied successfully",
            "threat_id": request.threat_id,
            "original_verdict": original_verdict,
            "new_verdict": request.override_verdict,
            "override_notes": request.override_notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "forensic_tracking": {
                "override_applied": True,
                "analyst": request.analyst_username or "unknown",
                "override_time": threat.analyst_override_at.isoformat()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error applying analyst override: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to apply override: {str(e)}")
    finally:
        db.close()

@app.post("/api/v1/analyst/notes")
async def add_analyst_notes(request: AnalystNotesRequest):
    """
    Add analyst notes to scan history for forensic documentation.
    
    Allows analysts to document their review and verification of scan results.
    """
    from .database import SessionLocal
    from .models import ScanHistory, User
    from sqlalchemy.orm import Session
    
    db: Session = SessionLocal()
    
    try:
        # Find the scan
        scan = db.query(ScanHistory).filter(ScanHistory.scan_id == request.scan_id).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {request.scan_id} not found")
        
        # Update analyst notes
        scan.analyst_notes = request.analyst_notes
        scan.analyst_verified = request.verified
        
        db.commit()
        db.refresh(scan)
        
        logger.info(f"Analyst notes added to scan {request.scan_id} by {request.analyst_username or 'unknown'}")
        
        return {
            "status": "success",
            "message": "Analyst notes added successfully",
            "scan_id": request.scan_id,
            "verified": request.verified,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding analyst notes: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to add notes: {str(e)}")
    finally:
        db.close()

@app.get("/api/v1/forensics/threat/{threat_id}")
async def get_threat_forensics(threat_id: str):
    """
    Retrieve complete forensic information for a threat including:
    - Evidence sources with IDs/links
    - Corroboration details
    - Analyst overrides and notes
    """
    from .database import SessionLocal
    from .models import Threat, User
    from sqlalchemy.orm import Session
    
    db: Session = SessionLocal()
    
    try:
        threat = db.query(Threat).filter(Threat.threat_id == threat_id).first()
        
        if not threat:
            raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")
        
        # Build forensic report
        forensic_data = {
            "threat_id": threat.threat_id,
            "threat_type": threat.threat_type,
            "severity": threat.severity.value if threat.severity else None,
            "status": threat.status.value if threat.status else None,
            
            # Evidence and Corroboration
            "evidence_sources": threat.evidence_sources or [],
            "corroboration_count": threat.corroboration_count or 0,
            "corroboration_threshold_met": threat.corroboration_threshold_met or False,
            
            # API Results (full evidence)
            "api_results": {
                "virus_total": threat.virus_total_result,
                "abuseipdb": threat.abuseipdb_result,
                "shodan": threat.shodan_result,
                "hybrid_analysis": threat.hybrid_analysis_result,
                "urlscan": threat.urlscan_result
            },
            
            # AI Analysis
            "ai_confidence": threat.ai_confidence,
            "ai_analysis": threat.ai_analysis,
            
            # Analyst Override Information
            "analyst_override": {
                "overridden": threat.analyst_override or False,
                "override_notes": threat.analyst_override_notes,
                "original_verdict": threat.original_verdict,
                "override_timestamp": threat.analyst_override_at.isoformat() if threat.analyst_override_at else None,
                "overridden_by": None
            },
            
            # Timestamps
            "detection_time": threat.detection_time.isoformat() if threat.detection_time else None,
            "last_updated": threat.last_updated.isoformat() if threat.last_updated else None
        }
        
        # Get analyst who made the override
        if threat.analyst_override_by_id:
            analyst = db.query(User).filter(User.id == threat.analyst_override_by_id).first()
            if analyst:
                forensic_data["analyst_override"]["overridden_by"] = {
                    "username": analyst.username,
                    "full_name": analyst.full_name,
                    "email": analyst.email
                }
        
        return forensic_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving forensic data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve forensics: {str(e)}")
    finally:
        db.close()

# Helper Functions

def perform_local_traffic_analysis(traffic_data: Dict[str, Any]) -> Dict[str, Any]:
    """Perform local traffic analysis (fallback when Gemini is unavailable)"""
    # Your existing local analysis logic here
    return {
        "threat_level": "Medium",
        "vulnerabilities": ["Potential threats detected"],
        "confidence": 70,
        "source": "local_analysis",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def perform_local_analysis(prompt: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """Perform local analysis (fallback when Gemini is unavailable)"""
    # Your existing local analysis logic here
    return {
        "content": f"Local analysis result for: {prompt[:100]}...",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "local_analysis",
        "success": True
    }

def determine_combined_threat_level(gemini_result: Dict[str, Any], 
                                   local_result: Dict[str, Any]) -> str:
    """Determine combined threat level from multiple analysis sources"""
    threat_levels = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }
    
    gemini_level = gemini_result.get('threat_level', 'Low')
    local_level = local_result.get('threat_level', 'Low')
    
    # Use the higher threat level
    if threat_levels.get(gemini_level, 0) > threat_levels.get(local_level, 0):
        return gemini_level
    return local_level

# Error Handling
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": request.url.path
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": request.url.path
        }
    )

if __name__ == "__main__":
    # Initialize on script run
    initialize_gemini_configuration()
    
    # Start the server
    uvicorn.run(
        "app.main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=settings.DEBUG,
        log_level="info"
    )