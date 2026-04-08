"""
Lightweight endpoint smoke tester that avoids TestClient compatibility issues
by using `httpx` with ASGI transport to call the FastAPI `app` directly.

This is more resilient across dependency versions of `starlette`/`fastapi`.
"""

import json
import sys
import warnings
import asyncio
from pathlib import Path

warnings.filterwarnings(
	"ignore",
	message=r".*datetime\.datetime\.utcnow\(\) is deprecated.*",
	category=DeprecationWarning,
)

# Resolve the repository root from this file so the import works under pytest,
# direct execution, and from any working directory.
REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_ROOT = REPO_ROOT / "server"
if str(SERVER_ROOT) not in sys.path:
	sys.path.insert(0, str(SERVER_ROOT))

from app.main import app

try:
	# Prefer the public ASGITransport if available
	from httpx import AsyncClient
	try:
		from httpx import ASGITransport
	except Exception:
		# older httpx versions expose ASGITransport under different path
		from httpx._transports.asgi import ASGITransport
except Exception as exc:
	print("httpx is required for this smoke test (install in .venv).", file=sys.stderr)
	raise


def pretty(resp):
	try:
		return json.dumps(resp.json(), indent=2)
	except Exception:
		return resp.text


def build_transport():
	return ASGITransport(app=app)


async def _test_endpoint_smoke_async():
	async with AsyncClient(transport=build_transport(), base_url="http://testserver") as client:
		health = await client.get("/api/v1/health")
		assert health.status_code == 200
		health_payload = health.json()
		assert health_payload.get("status") in {"healthy", "degraded"}
		assert "gemini" in health_payload

		scan = await client.post("/api/v1/scan", json={"target": "example.com", "include_report": False})
		assert scan.status_code in {200, 201}
		scan_payload = scan.json()
		assert any(key in scan_payload for key in ("status", "verdict", "analysis"))

		url_scan = await client.post("/api/v1/scan/url", json={"target": "https://example.com", "include_report": False})
		assert url_scan.status_code in {200, 201}

		hash_scan = await client.post("/api/v1/scan/hash", json={"target": "d41d8cd98f00b204e9800998ecf8427e", "include_report": False})
		assert hash_scan.status_code in {200, 201}


def test_endpoint_smoke():
	asyncio.run(_test_endpoint_smoke_async())


if __name__ == '__main__':
	import asyncio


	async def main():
		async with AsyncClient(transport=build_transport(), base_url="http://testserver") as client:
			base = ""
			print('GET /api/v1/health ->', pretty(await client.get(f"{base}/api/v1/health")))

			resp = await client.post(f"{base}/api/v1/scan", json={'target': 'example.com', 'include_report': False})
			print('POST /api/v1/scan ->', resp.status_code, pretty(resp))

			resp2 = await client.post(f"{base}/api/v1/scan/url", json={'target': 'https://example.com', 'include_report': False})
			print('POST /api/v1/scan/url ->', resp2.status_code, pretty(resp2))

			resp3 = await client.post(f"{base}/api/v1/scan/hash", json={'target': 'd41d8cd98f00b204e9800998ecf8427e', 'include_report': False})
			print('POST /api/v1/scan/hash ->', resp3.status_code, pretty(resp3))

	asyncio.run(main())
