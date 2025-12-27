import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def http_get(url, timeout=5):
    try:
        req = Request(url)
        with urlopen(req, timeout=timeout) as r:
            content = r.read().decode("utf-8", errors="ignore")
            return {"url": url, "status": r.getcode(), "body_snippet": content[:200]}
    except Exception as e:
        return {"url": url, "error": str(e)}


def http_post_json(url, data, timeout=5):
    try:
        payload = json.dumps(data).encode("utf-8")
        req = Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=timeout) as r:
            resp = r.read().decode("utf-8", errors="ignore")
            return {"url": url, "status": r.getcode(), "response": resp}
    except HTTPError as e:
        return {"url": url, "error": f"HTTPError {e.code}: {e.reason}"}
    except URLError as e:
        return {"url": url, "error": f"URLError: {e.reason}"}
    except Exception as e:
        return {"url": url, "error": str(e)}


def main():
    endpoints = []
    endpoints.append(http_get("http://localhost:8000"))
    endpoints.append(http_get("http://localhost:8000/api/v1/health"))
    endpoints.append(
        http_post_json(
            "http://localhost:8000/api/scan",
            {"type": "url", "target": "http://example.com"},
        )
    )
    endpoints.append(http_get("http://localhost:8000/api/scans"))
    endpoints.append(
        http_post_json(
            "http://localhost:8000/api/reports/generate", {"target": "example.com"}
        )
    )
    endpoints.append(http_get("http://localhost:8000/api/reports"))

    print(json.dumps(endpoints, indent=2))


if __name__ == "__main__":
    main()
