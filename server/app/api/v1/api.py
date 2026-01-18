from fastapi import APIRouter

from .endpoints import advanced_reports, ai_threat_prediction, analyze, auth, dashboard, defense, network_defense, reports, scan, threats

api_router = APIRouter()

# Auth routes
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

# Scan routes
api_router.include_router(scan.router, prefix="/scan", tags=["scan"])

# Threats routes
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])

# Dashboard routes
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])

# Reports routes
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])

# Advanced Reports routes
api_router.include_router(advanced_reports.router, prefix="/advanced-reports", tags=["advanced-reports"])

# Network Defense routes
api_router.include_router(network_defense.router, prefix="/network", tags=["network-defense"])

# AI Threat Prediction routes
api_router.include_router(ai_threat_prediction.router, prefix="/ai-prediction", tags=["ai-prediction"])

# Defense Management routes (NEW v3.0)
api_router.include_router(defense.router, prefix="/defense", tags=["defense"])

# AI Activity Analysis routes (NEW v3.0)
api_router.include_router(analyze.router, prefix="/analyze", tags=["analyze"])
