from fastapi.testclient import TestClient

from server.app.main import app

client = TestClient(app)

print('GET /api/v1/health ->', client.get('/api/v1/health').json())

# Universal scan (uses threat_analyzer stubs) – send simple target
resp = client.post('/api/v1/scan', json={'target': 'example.com', 'include_report': False})
print('POST /api/v1/scan ->', resp.status_code, resp.json())

# URL scan
resp2 = client.post('/api/v1/scan/url', json={'target': 'https://example.com', 'include_report': False})
print('POST /api/v1/scan/url ->', resp2.status_code, resp2.json())

# Hash scan (submit random hash)
resp3 = client.post('/api/v1/scan/hash', json={'target': 'd41d8cd98f00b204e9800998ecf8427e', 'include_report': False})
print('POST /api/v1/scan/hash ->', resp3.status_code, resp3.json())
