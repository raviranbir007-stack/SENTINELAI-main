#!/usr/bin/env python3
"""
SENTINEL-AI API Testing Script
Tests all endpoints with threat detection and report generation
Run this after starting run_server.py
"""

import json

import requests

# API Configuration
API_BASE_URL = "http://localhost:8000/api/v1"
HEADERS = {"Content-Type": "application/json"}
REQUEST_TIMEOUT = 30  # seconds - prevent tests from hanging


def _get_first_threat_id():
    """Fetch the first available threat ID from the API, if any."""
    response = requests.get(f"{API_BASE_URL}/threats?time_range=24h", timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    payload = response.json() if response.content else {}
    threats = payload.get("threats") if isinstance(payload, dict) else []
    if not threats:
        return None
    first = threats[0] if isinstance(threats[0], dict) else {}
    return first.get("threat_id") or first.get("id") or first.get("scan_id")


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    END = "\033[0m"


def print_test(test_name: str):
    print(f"\n{Colors.BLUE}=== {test_name} ==={Colors.END}")


def print_success(message: str):
    print(f"{Colors.GREEN}✓ {message}{Colors.END}")


def print_error(message: str):
    print(f"{Colors.RED}✗ {message}{Colors.END}")


def print_info(message: str):
    print(f"{Colors.YELLOW}ℹ {message}{Colors.END}")


def test_health_check():
    """Test health endpoint"""
    print_test("Health Check")
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=REQUEST_TIMEOUT)
        assert response.status_code == 200, (
            f"Health check failed with status {response.status_code}"
        )
        data = response.json()
        print_success(f"Server is healthy: {data}")
    except Exception as e:
        print_error(f"Error connecting to server: {e}")
        raise


def test_threats_24h():
    """Test threats endpoint with 24h filter"""
    print_test("Get Threats - Last 24 Hours")
    try:
        response = requests.get(f"{API_BASE_URL}/threats?time_range=24h", timeout=REQUEST_TIMEOUT)
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success(
            f"Retrieved {data.get('total_threats', 0)} threats from last 24 hours"
        )
        print_info(f"Time range: {data.get('time_range')}")
        print_info(f"Start date: {data.get('start_date')}")

        if data.get("threats"):
            print_info(f"First threat: {data['threats'][0].get('name')}")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_threats_7d():
    """Test threats endpoint with 7d filter"""
    print_test("Get Threats - Last 7 Days")
    try:
        response = requests.get(f"{API_BASE_URL}/threats?time_range=7d", timeout=REQUEST_TIMEOUT)
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success(
            f"Retrieved {data.get('total_threats', 0)} threats from last 7 days"
        )
        if data.get("threats"):
            print_info(
                f"Sample threat types: {[t.get('type') for t in data['threats'][:3]]}"
            )
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_threats_30d():
    """Test threats endpoint with 30d filter"""
    print_test("Get Threats - Last 30 Days")
    try:
        response = requests.get(f"{API_BASE_URL}/threats?time_range=30d", timeout=REQUEST_TIMEOUT)
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success(
            f"Retrieved {data.get('total_threats', 0)} threats from last 30 days"
        )
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_threat_detail():
    """Test threat detail endpoint"""
    print_test("Get Threat Details")
    try:
        threat_id = _get_first_threat_id()
        if not threat_id:
            print_info("No current threats available; skipping detail test")
            return

        response = requests.get(f"{API_BASE_URL}/threats/{threat_id}", timeout=REQUEST_TIMEOUT)
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success(f"Retrieved threat details: {data.get('name')}")
        print_info(f"Threat ID: {data.get('threat_id')}")
        print_info(f"Severity: {data.get('severity')}")
        print_info(f"Source: {data.get('source')}")
        print_info(f"Location: {data.get('location')}")
        print_info(f"Confidence: {data.get('confidence_score')}%")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_scan_ip():
    """Test IP scanning endpoint"""
    print_test("Scan IP Address")
    try:
        payload = {"ip_address": "192.168.1.50"}
        response = requests.post(
            f"{API_BASE_URL}/threats/scan-ip", json=payload, headers=HEADERS, timeout=REQUEST_TIMEOUT
        )
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success(f"IP scan completed for {payload['ip_address']}")
        print_info(f"Threat level: {data.get('threat_level')}")
        print_info(f"Reputation score: {data.get('reputation_score')}")
        if data.get("api_results"):
            print_info(f"API Results: {json.dumps(data['api_results'], indent=2)}")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_dashboard_summary():
    """Test dashboard summary endpoint"""
    print_test("Dashboard Summary")
    try:
        response = requests.get(f"{API_BASE_URL}/dashboard/summary?time_range=24h", timeout=REQUEST_TIMEOUT)
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success("Retrieved dashboard summary")
        print_info(f"Time range: {data.get('time_range')}")
        print_info(f"Total scans: {data.get('total_scans')}")
        print_info(f"Threats detected: {data.get('threats_detected')}")
        print_info(f"Critical threats: {data.get('critical_threats')}")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_dashboard_threats():
    """Test dashboard threats endpoint"""
    print_test("Dashboard Threats")
    try:
        response = requests.get(
            f"{API_BASE_URL}/dashboard/threats?time_range=24h&severity=critical",
            timeout=REQUEST_TIMEOUT
        )
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success(f"Retrieved {len(data)} critical threats")
        if data:
            for threat in data[:2]:
                print_info(f"  - {threat.get('name')} ({threat.get('severity')})")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_dashboard_stats():
    """Test dashboard stats endpoint"""
    print_test("Dashboard Statistics")
    try:
        response = requests.get(f"{API_BASE_URL}/dashboard/stats?time_range=7d", timeout=REQUEST_TIMEOUT)
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success("Retrieved dashboard statistics")
        print_info(f"Critical threats: {data.get('critical_threats')}")
        print_info(f"High threats: {data.get('high_threats')}")
        print_info(f"Medium threats: {data.get('medium_threats')}")
        print_info(f"Low threats: {data.get('low_threats')}")
        print_info(f"Files scanned: {data.get('files_scanned')}")
        print_info(f"URLs scanned: {data.get('urls_scanned')}")
        print_info(f"IPs scanned: {data.get('ips_scanned')}")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_get_reports():
    """Test get reports endpoint - currently not implemented"""
    print_test("Get Reports List")
    try:
        response = requests.get(f"{API_BASE_URL}/reports?time_range=24h", timeout=REQUEST_TIMEOUT)
        assert response.status_code in {200, 404}, f"Failed with status {response.status_code}"
        if response.status_code == 200:
            data = response.json()
            print_success(f"Retrieved {data.get('total_reports', 0)} reports")
            if data.get("reports"):
                for report in data["reports"][:2]:
                    print_info(f"  - {report.get('report_id')}: {report.get('title')}")
        elif response.status_code == 404:
            print_info("GET /reports endpoint not yet implemented (404) - skipping")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_generate_report():
    """Test report generation endpoint"""
    print_test("Generate PDF Report")
    try:
        payload = {
            "target": "192.168.1.100",
            "risk_score": 7.5,
            "threats": ["Malware Detected", "Suspicious Activity"],
            "scan_summary": "Test scan summary for THR001"
        }
        response = requests.post(
            f"{API_BASE_URL}/reports/generate", 
            json=payload,
            headers=HEADERS, 
            timeout=REQUEST_TIMEOUT
        )
        assert response.status_code == 200, f"Failed with status {response.status_code}: {response.text}"
        # Response is a PDF file
        if response.headers.get("content-type") == "application/pdf":
            print_success("PDF report generated successfully")
            print_info(f"Content-Type: {response.headers.get('content-type')}")
            print_info(f"File size: {len(response.content)} bytes")
        else:
            data = response.json()
            print_success(f"Report generated: {data.get('report_text', 'Generated')[:100]}...")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_download_report():
    """Test report download endpoint"""
    print_test("Download Report PDF")
    try:
        # First, generate a report from a scan
        payload = {
            "target": "test-download-report",
            "risk_score": 6.0,
            "threats": ["Test Threat"],
            "scan_summary": "Test download functionality"
        }
        response = requests.post(
            f"{API_BASE_URL}/reports/generate",
            json=payload,
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT
        )
        assert response.status_code == 200, f"Failed to generate report: {response.status_code}"
        
        content_type = str(response.headers.get("content-type") or "").lower()

        # Endpoint can return either a streamed PDF or JSON fallback payload
        if content_type.startswith("application/pdf"):
            print_success("PDF report generated and downloaded successfully")
            print_info(f"Content-Type: {response.headers.get('content-type')}")
            print_info(f"File size: {len(response.content)} bytes")

            # Save to file
            filename = f"/tmp/Threat_Report_test.pdf"
            with open(filename, "wb") as f:
                f.write(response.content)
            print_info(f"Saved to: {filename}")
        elif "application/json" in content_type:
            data = response.json()
            report_text = str(data.get("report_text") or "").strip()
            assert report_text, "JSON fallback missing report_text"
            print_success("Report returned JSON fallback payload")
            print_info(f"Preview: {report_text[:100]}...")
        else:
            raise AssertionError(
                f"Response is not a PDF: {response.headers.get('content-type')}"
            )
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def test_respond_to_threat():
    """Test threat response endpoint"""
    print_test("Respond to Threat")
    try:
        threat_id = _get_first_threat_id()
        if not threat_id:
            print_info("No current threats available; skipping response test")
            return

        response = requests.post(
            f"{API_BASE_URL}/threats/{threat_id}/respond", headers=HEADERS, timeout=REQUEST_TIMEOUT
        )
        assert response.status_code == 200, f"Failed with status {response.status_code}"
        data = response.json()
        print_success("Response action executed")
        print_info(f"Threat ID: {data.get('threat_id')}")
        print_info(f"Status: {data.get('status')}")
        print_info(f"Action: {data.get('action')}")
    except Exception as e:
        print_error(f"Error: {e}")
        raise


def _run_test_safely(test_func):
    """Run a test function for CLI mode and return pass/fail without raising."""
    try:
        test_func()
        return True
    except Exception:
        return False


def run_all_tests():
    """Run all API tests"""
    print(
        f"\n{Colors.BLUE}╔════════════════════════════════════════════════════════════╗{Colors.END}"
    )
    print(
        f"{Colors.BLUE}║  SENTINEL-AI API Testing Suite                             ║{Colors.END}"
    )
    print(
        f"{Colors.BLUE}║  Threat Detection & Report Generation                      ║{Colors.END}"
    )
    print(
        f"{Colors.BLUE}╚════════════════════════════════════════════════════════════╝{Colors.END}"
    )

    # Run tests
    results = {}

    # Health check first
    if not _run_test_safely(test_health_check):
        print_error("Cannot proceed - server is not responding")
        return

    # Threat endpoints
    results["threats_24h"] = _run_test_safely(test_threats_24h)
    results["threats_7d"] = _run_test_safely(test_threats_7d)
    results["threats_30d"] = _run_test_safely(test_threats_30d)
    results["threat_detail"] = _run_test_safely(test_threat_detail)
    results["scan_ip"] = _run_test_safely(test_scan_ip)
    results["respond_threat"] = _run_test_safely(test_respond_to_threat)

    # Dashboard endpoints
    results["dashboard_summary"] = _run_test_safely(test_dashboard_summary)
    results["dashboard_threats"] = _run_test_safely(test_dashboard_threats)
    results["dashboard_stats"] = _run_test_safely(test_dashboard_stats)

    # Report endpoints
    results["get_reports"] = _run_test_safely(test_get_reports)
    results["generate_report"] = _run_test_safely(test_generate_report)
    results["download_report"] = _run_test_safely(test_download_report)

    # Summary
    print(f"\n{Colors.BLUE}=== Test Summary ==={Colors.END}")
    passed = sum(1 for v in results.values() if v)
    total = len(results)

    if passed == total:
        print_success(f"All {total} tests passed! ✓")
    else:
        print_error(f"{passed}/{total} tests passed")
        print("\nFailed tests:")
        for test_name, result in results.items():
            if not result:
                print(f"  - {test_name}")


if __name__ == "__main__":
    try:
        run_all_tests()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Testing interrupted by user{Colors.END}")
    except Exception as e:
        print_error(f"Unexpected error: {e}")
