"""
Lightweight endpoint smoke tester that avoids TestClient compatibility issues
by using `httpx` with ASGI transport to call the FastAPI `app` directly.

This is more resilient across dependency versions of `starlette`/`fastapi`.
"""

import json
import sys

from server.app.main import app

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


transport = ASGITransport(app=app)


async def main():
	async with AsyncClient(transport=transport) as client:
		base = "http://testserver"
		print('GET /api/v1/health ->', pretty(await client.get(f"{base}/api/v1/health")))

		resp = await client.post(f"{base}/api/v1/scan", json={'target': 'example.com', 'include_report': False})
		print('POST /api/v1/scan ->', resp.status_code, pretty(resp))

		resp2 = await client.post(f"{base}/api/v1/scan/url", json={'target': 'https://example.com', 'include_report': False})
		print('POST /api/v1/scan/url ->', resp2.status_code, pretty(resp2))

		resp3 = await client.post(f"{base}/api/v1/scan/hash", json={'target': 'd41d8cd98f00b204e9800998ecf8427e', 'include_report': False})
		print('POST /api/v1/scan/hash ->', resp3.status_code, pretty(resp3))


if __name__ == '__main__':
	import asyncio

	asyncio.run(main())
