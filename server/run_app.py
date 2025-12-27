#!/usr/bin/env python
"""
Windows-safe uvicorn runner that avoids Proactor issues.
"""
import asyncio
import sys
import traceback

# Set Windows event loop policy to avoid Proactor issues
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import uvicorn

if __name__ == "__main__":
    try:
        print("[*] Starting SENTINEL-AI server...")
        print(f"[*] Platform: {sys.platform}")
        print(f"[*] Event loop policy: {asyncio.get_event_loop_policy()}")

        uvicorn.run(
            "app.main:app",
            host="127.0.0.1",
            port=8000,
            log_level="info",
            access_log=True,
        )
    except Exception as e:
        print(f"[ERROR] Server crashed: {e}")
        traceback.print_exc()
        sys.exit(1)
