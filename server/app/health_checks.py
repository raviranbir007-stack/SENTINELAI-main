"""
Dependency health checks for SENTINEL-AI server startup
"""
import logging
import os
from typing import Dict, List, Tuple
from sqlalchemy import text

logger = logging.getLogger(__name__)


async def check_database_connection(db_engine) -> Tuple[bool, str]:
    """Check if database connection works."""
    try:
        # Try to execute a simple query
        async with db_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        return True, "Database connection OK"
    except Exception as e:
        return False, f"Database connection failed: {str(e)[:100]}"


def check_ml_models() -> Tuple[bool, str]:
    """Check if ML models are loadable."""
    try:
        from .ml_models import AnomalyDetectionModel, ThreatPredictionModel
        
        # Try to instantiate models
        _ = AnomalyDetectionModel()
        _ = ThreatPredictionModel()
        
        return True, "ML models loaded OK"
    except Exception as e:
        return False, f"ML models failed to load: {str(e)[:100]}"


def check_gemini_config() -> Tuple[bool, str]:
    """Check if Gemini API is properly configured."""
    try:
        from .config import settings
        from .gemini_integration import get_gemini_client
        
        has_key = bool(
            getattr(settings, 'GEMINI_API_KEY', None)
            or os.getenv('GOOGLE_API_KEY')
            or os.getenv('GEMINI_API_KEYS')
            or os.getenv('GOOGLE_API_KEYS')
        )
        if not has_key:
            for idx in range(1, 21):
                if os.getenv(f'GEMINI_API_KEY_{idx}') or os.getenv(f'GOOGLE_API_KEY_{idx}'):
                    has_key = True
                    break

        if not has_key:
            return False, "Gemini API keys not configured"
        
        client = get_gemini_client()
        if not client.is_available():
            return False, "Gemini client is not available"
        
        return True, "Gemini API configuration OK"
    except Exception as e:
        # Gemini is optional, so this is a warning
        logger.warning(f"Gemini check: {str(e)[:100]}")
        return True, f"Gemini optional: {str(e)[:50]}"


def check_config_validity() -> Tuple[bool, str]:
    """Check if critical configuration is set."""
    try:
        from .config import settings
        
        required_attrs = [
            'DEBUG',
            'DATABASE_URL',
            'SECRET_KEY',
        ]
        
        missing = []
        for attr in required_attrs:
            if not getattr(settings, attr, None):
                missing.append(attr)
        
        if missing:
            return False, f"Missing required config: {', '.join(missing)}"
        
        return True, "Configuration valid"
    except Exception as e:
        return False, f"Config check failed: {str(e)[:100]}"


async def run_health_checks(db_engine=None) -> Dict[str, Tuple[bool, str]]:
    """
    Run all health checks for dependencies.
    
    Returns:
        {check_name: (passed, message), ...}
    """
    results = {}
    
    # Config check
    passed, msg = check_config_validity()
    results['config'] = (passed, msg)
    if not passed:
        logger.error(f"❌ Config check: {msg}")
    else:
        logger.debug(f"✅ Config check: {msg}")
    
    # Database check
    if db_engine:
        passed, msg = await check_database_connection(db_engine)
        results['database'] = (passed, msg)
        if not passed:
            logger.error(f"❌ Database check: {msg}")
        else:
            logger.debug(f"✅ Database check: {msg}")
    
    # ML Models check
    passed, msg = check_ml_models()
    results['ml_models'] = (passed, msg)
    if not passed:
        logger.error(f"❌ ML Models check: {msg}")
    else:
        logger.debug(f"✅ ML Models check: {msg}")
    
    # Gemini check (optional)
    passed, msg = check_gemini_config()
    results['gemini'] = (passed, msg)
    if not passed:
        logger.warning(f"⚠️  Gemini check: {msg}")
    else:
        logger.debug(f"✅ Gemini check: {msg}")
    
    return results


async def validate_startup(db_engine=None) -> bool:
    """
    Validate that all critical dependencies are available.
    
    Returns:
        True if all critical checks pass, False otherwise
    """
    results = await run_health_checks(db_engine)
    
    critical_checks = ['config', 'ml_models']
    failed = [
        check for check, (passed, _) in results.items()
        if check in critical_checks and not passed
    ]
    
    if failed:
        logger.error(f"❌ Critical health checks failed: {', '.join(failed)}")
        return False

    passed_count = sum(1 for passed, _ in results.values() if passed)
    logger.info("✅ Health checks passed (%d/%d)", passed_count, len(results))
    return True
