"""
Quick Start Testing Script
Tests the SENTINEL-AI threat detection system
"""

# Utility script (not a pytest test module)
__test__ = False

import asyncio

import httpx

BASE_URL = "http://localhost:8000/api/v1/scan"


async def test_universal_scan():
    """Test universal scan endpoint with different input types"""

    print("\n" + "=" * 60)
    print("TESTING UNIVERSAL SCAN ENDPOINT")
    print("=" * 60)

    test_cases = [
        {
            "name": "IP Address Scan",
            "target": "8.8.8.8",
            "description": "Scan Google DNS server",
        },
        {
            "name": "URL Scan",
            "target": "https://example.com",
            "description": "Scan example.com domain",
        },
        {
            "name": "Domain Scan",
            "target": "example.com",
            "description": "Scan domain without protocol",
        },
        {
            "name": "File Hash Scan",
            "target": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "description": "Scan SHA256 hash (empty file)",
        },
        {
            "name": "File Name Scan",
            "target": "report.docx",
            "description": "Scan file name/type for heuristic file analysis",
        },
    ]

    async with httpx.AsyncClient(timeout=30.0) as client:
        for test_case in test_cases:
            print(f"\n{test_case['name']}")
            print(f"Description: {test_case['description']}")
            print(f"Target: {test_case['target']}")
            print("-" * 60)

            try:
                response = await client.post(
                    f"{BASE_URL}/scan",
                    json={"target": test_case["target"], "include_report": False},
                )

                if response.status_code == 200:
                    result = response.json()
                    print(f"Status: {result['status']}")
                    print(f"Detected Type: {result['detected_type']}")
                    print(f"Threat Level: {result['threat_level']}")
                    print(f"Confidence: {result['confidence']:.1%}")
                    print(f"Threats Detected: {result['threats_detected']}")

                    if result["analysis"]["threat_indicators"]:
                        print("\nThreats Found:")
                        for threat in result["analysis"]["threat_indicators"]:
                            print(f"  - {threat['source']}: {threat['indicator']}")
                            print(f"    Severity: {threat['severity']}")
                else:
                    print(f"Error: {response.status_code}")
                    print(response.text)

            except Exception as e:
                print(f"Error: {str(e)}")


async def test_ip_scan():
    """Test IP-specific scan"""

    print("\n" + "=" * 60)
    print("TESTING IP SCAN ENDPOINT")
    print("=" * 60)

    test_ips = ["8.8.8.8", "1.1.1.1", "127.0.0.1"]

    async with httpx.AsyncClient(timeout=30.0) as client:
        for ip in test_ips:
            print(f"\nScanning: {ip}")
            print("-" * 60)

            try:
                response = await client.post(
                    f"{BASE_URL}/ip", json={"target": ip, "include_report": False}
                )

                if response.status_code == 200:
                    result = response.json()
                    print(f"Threat Level: {result['threat_level']}")
                    print(f"Confidence: {result['confidence']:.1%}")
                    print(
                        f"APIs Used: {', '.join(result['analysis']['api_results'].get('apis_called', []))}"
                    )
                else:
                    print(f"Error: {response.status_code}")

            except Exception as e:
                print(f"Error: {str(e)}")


async def test_url_scan():
    """Test URL-specific scan"""

    print("\n" + "=" * 60)
    print("TESTING URL SCAN ENDPOINT")
    print("=" * 60)

    test_urls = ["https://example.com", "https://google.com", "https://github.com"]

    async with httpx.AsyncClient(timeout=30.0) as client:
        for url in test_urls:
            print(f"\nScanning: {url}")
            print("-" * 60)

            try:
                response = await client.post(
                    f"{BASE_URL}/url", json={"target": url, "include_report": False}
                )

                if response.status_code == 200:
                    result = response.json()
                    print(f"Threat Level: {result['threat_level']}")
                    print(f"Confidence: {result['confidence']:.1%}")
                    print(f"Threats Detected: {result['threats_detected']}")
                else:
                    print(f"Error: {response.status_code}")

            except Exception as e:
                print(f"Error: {str(e)}")


async def test_hash_scan():
    """Test file hash scan"""

    print("\n" + "=" * 60)
    print("TESTING HASH SCAN ENDPOINT")
    print("=" * 60)

    # Example hashes (these are safe/clean files)
    test_hashes = [
        {
            "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "name": "Empty file hash",
        }
    ]

    async with httpx.AsyncClient(timeout=30.0) as client:
        for test_hash in test_hashes:
            print(f"\nScanning: {test_hash['name']}")
            print(f"Hash: {test_hash['hash'][:32]}...")
            print("-" * 60)

            try:
                response = await client.post(
                    f"{BASE_URL}/hash",
                    json={"target": test_hash["hash"], "include_report": False},
                )

                if response.status_code == 200:
                    result = response.json()
                    print(f"Threat Level: {result['threat_level']}")
                    print(f"Confidence: {result['confidence']:.1%}")
                    print(f"Threats Detected: {result['threats_detected']}")
                else:
                    print(f"Error: {response.status_code}")

            except Exception as e:
                print(f"Error: {str(e)}")


async def test_with_report():
    """Test scan with PDF report generation"""

    print("\n" + "=" * 60)
    print("TESTING SCAN WITH PDF REPORT")
    print("=" * 60)

    print("\nScanning with report generation...")
    print("-" * 60)

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.post(
                f"{BASE_URL}/scan", json={"target": "8.8.8.8", "include_report": True}
            )

            if response.status_code == 200:
                result = response.json()
                print(f"Threat Level: {result['threat_level']}")
                print(f"Confidence: {result['confidence']:.1%}")

                if "report" in result:
                    print("\nPDF Report Generated:")
                    print(f"  Format: {result['report']['format']}")
                    print(f"  Size: {result['report']['size']} bytes")

                    # Save PDF to file
                    pdf_data = bytes.fromhex(result["report"]["data"])
                    with open("threat_report.pdf", "wb") as f:
                        f.write(pdf_data)
                    print("  Saved to: threat_report.pdf")
                else:
                    print(
                        "Note: PDF report not generated (dependencies may not be installed)"
                    )
            else:
                print(f"Error: {response.status_code}")

        except Exception as e:
            print(f"Error: {str(e)}")


async def main():
    """Run all tests"""

    print("\n" + "=" * 60)
    print("SENTINEL-AI THREAT DETECTION SYSTEM - TEST SUITE")
    print("=" * 60)
    print("\nNote: Ensure the server is running on http://localhost:8000")
    print("Run: python run_server.py")

    try:
        # Test connectivity
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.get(
                "http://localhost:8000/api/v1/scan/results/test"
            )
            print("\n✓ Server is running and accessible")
    except Exception as e:
        print(f"\n✗ Cannot connect to server: {str(e)}")
        print("Please start the server first: python run_server.py")
        return

    # Run tests
    await test_universal_scan()
    await test_ip_scan()
    await test_url_scan()
    await test_hash_scan()
    await test_with_report()

    print("\n" + "=" * 60)
    print("TEST SUITE COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
