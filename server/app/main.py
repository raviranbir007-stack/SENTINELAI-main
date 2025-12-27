from dotenv import load_dotenv

# Verify key loaded\nkey = os.getenv("GEMINI_API_KEY")\nif not key:\n    print("❌ CRITICAL: No Gemini API key in .env!")\n    print("   Edit .env file and add: GEMINI_API_KEY=your_key")\n    print("   Get key from: https://makersuite.google.com/app/apikey")\n    import sys\n    sys.exit(1)\nelse:\n    print(f"✅ Gemini API key loaded ({len(key)} chars)")\n    os.environ["GEMINI_API_KEY"] = key\n

# Verify Gemini API key\nGEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")\nif GEMINI_API_KEY:\n    print(f"✅ Gemini API key loaded: {GEMINI_API_KEY[:10]}... ({len(GEMINI_API_KEY)} chars)")\n    os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY\nelse:\n    print("❌ ERROR: Gemini API key not found in .env file!")\n    print("   Make sure .env has GEMINI_API_KEY=your_key")\n

load_dotenv(dotenv_path="../.env.example")

# Verify key loaded\nkey = os.getenv("GEMINI_API_KEY")\nif not key:\n    print("❌ CRITICAL: No Gemini API key in .env!")\n    print("   Edit .env file and add: GEMINI_API_KEY=your_key")\n    print("   Get key from: https://makersuite.google.com/app/apikey")\n    import sys\n    sys.exit(1)\nelse:\n    print(f"✅ Gemini API key loaded ({len(key)} chars)")\n    os.environ["GEMINI_API_KEY"] = key\n

# Verify Gemini API key\nGEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")\nif GEMINI_API_KEY:\n    print(f"✅ Gemini API key loaded: {GEMINI_API_KEY[:10]}... ({len(GEMINI_API_KEY)} chars)")\n    os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY\nelse:\n    print("❌ ERROR: Gemini API key not found in .env file!")\n    print("   Make sure .env has GEMINI_API_KEY=your_key")\n
import os

# Verify Gemini API key is loaded
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

if not GEMINI_API_KEY:
    print("❌ ERROR: No Gemini API key found!")
    print("   Check your .env.example file contains either:")
    print("   GEMINI_API_KEY=your_key_here")
    print("   OR")
    print("   GOOGLE_API_KEY=your_key_here")
    print("   Then restart the server.")
else:
    print(f"✅ Gemini API key loaded ({len(GEMINI_API_KEY)} chars)")
    # Set it for Google's library
    os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import compat
from .api.v1.api import api_router
from .config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="SENTINEL-AI: AI-Powered Threat Detection System",
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
)

# Add CORS middleware with explicit OPTIONS support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in DEBUG mode
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=(
        ["*"] if settings.DEBUG else ["sentinel-ai.local", "api.sentinel-ai.local"]
    ),
)

# Mount static files (if exists)
static_path = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")

# Include API router
app.include_router(api_router, prefix=settings.API_V1_PREFIX)
# Compatibility: also expose the same functionality at /api/* for the new frontend
app.include_router(compat.router, prefix="/api")


@app.get("/")
async def root():
    """Serve the frontend files with correct Content-Type headers."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    # Prefer the main `index.html` if present; fall back to `lovable-index.html`.
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
    }


@app.get("/api/v1/health")
async def health():
    return {"status": "healthy", "service": "SENTINEL-AI API"}


@app.get("/cors-test")
async def cors_test_page():
    """Serve CORS test page."""
    test_path = os.path.join(os.path.dirname(__file__), "static", "cors-test.html")
    if os.path.exists(test_path):
        return FileResponse(test_path, media_type="text/html")
    return {"error": "Test page not found"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)