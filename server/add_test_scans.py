"""
Add test scan data to database for report generation testing
"""
import asyncio
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.database import AsyncSessionLocal
from app.models import ScanHistory


async def add_test_scans():
    """Add sample scan data for testing reports"""
    async with AsyncSessionLocal() as db:
        try:
            # Create test scans with different timestamps
            test_scans = [
                # Recent scans (last 24h)
                {
                    "scan_id": f"TEST_24H_1_{int(datetime.utcnow().timestamp())}",
                    "target": "8.8.8.8",
                    "target_type": "ip",
                    "threat_level": "safe",
                    "confidence": 0.95,
                    "threats_detected": 0,
                    "analysis_data": {"verdict": "safe", "confidence": 0.95},
                    "scan_timestamp": datetime.utcnow() - timedelta(hours=2),
                },
                {
                    "scan_id": f"TEST_24H_2_{int(datetime.utcnow().timestamp())}",
                    "target": "malicious-site.example.com",
                    "target_type": "domain",
                    "threat_level": "malicious",
                    "confidence": 0.88,
                    "threats_detected": 5,
                    "analysis_data": {"verdict": "malicious", "confidence": 0.88},
                    "scan_timestamp": datetime.utcnow() - timedelta(hours=5),
                },
                {
                    "scan_id": f"TEST_24H_3_{int(datetime.utcnow().timestamp())}",
                    "target": "https://google.com",
                    "target_type": "url",
                    "threat_level": "safe",
                    "confidence": 0.99,
                    "threats_detected": 0,
                    "analysis_data": {"verdict": "safe", "confidence": 0.99},
                    "scan_timestamp": datetime.utcnow() - timedelta(hours=12),
                },
                # 7 days scans
                {
                    "scan_id": f"TEST_7D_1_{int(datetime.utcnow().timestamp())}",
                    "target": "192.168.1.100",
                    "target_type": "ip",
                    "threat_level": "suspicious",
                    "confidence": 0.65,
                    "threats_detected": 2,
                    "analysis_data": {"verdict": "suspicious", "confidence": 0.65},
                    "scan_timestamp": datetime.utcnow() - timedelta(days=3),
                },
                {
                    "scan_id": f"TEST_7D_2_{int(datetime.utcnow().timestamp())}",
                    "target": "malware.exe",
                    "target_type": "file",
                    "threat_level": "malicious",
                    "confidence": 0.92,
                    "threats_detected": 8,
                    "analysis_data": {"verdict": "malicious", "confidence": 0.92},
                    "scan_timestamp": datetime.utcnow() - timedelta(days=5),
                },
                # 30 days scans
                {
                    "scan_id": f"TEST_30D_1_{int(datetime.utcnow().timestamp())}",
                    "target": "a1b2c3d4e5f6",
                    "target_type": "hash",
                    "threat_level": "safe",
                    "confidence": 0.78,
                    "threats_detected": 0,
                    "analysis_data": {"verdict": "safe", "confidence": 0.78},
                    "scan_timestamp": datetime.utcnow() - timedelta(days=15),
                },
                {
                    "scan_id": f"TEST_30D_2_{int(datetime.utcnow().timestamp())}",
                    "target": "suspicious-domain.com",
                    "target_type": "domain",
                    "threat_level": "suspicious",
                    "confidence": 0.72,
                    "threats_detected": 3,
                    "analysis_data": {"verdict": "suspicious", "confidence": 0.72},
                    "scan_timestamp": datetime.utcnow() - timedelta(days=20),
                },
                {
                    "scan_id": f"TEST_30D_3_{int(datetime.utcnow().timestamp())}",
                    "target": "https://phishing-site.example",
                    "target_type": "url",
                    "threat_level": "malicious",
                    "confidence": 0.95,
                    "threats_detected": 12,
                    "analysis_data": {"verdict": "malicious", "confidence": 0.95},
                    "scan_timestamp": datetime.utcnow() - timedelta(days=28),
                },
            ]

            # Add scans to database
            for scan_data in test_scans:
                scan = ScanHistory(**scan_data)
                db.add(scan)

            await db.commit()
            
            print("✅ Successfully added test scan data!")
            print(f"✅ Added {len(test_scans)} test scans")
            print("\nScan distribution:")
            print(f"  • Last 24h: 3 scans")
            print(f"  • Last 7 days: 5 scans (includes 24h)")
            print(f"  • Last 30 days: 8 scans (includes all)")
            print("\nThreat levels:")
            print(f"  • Safe: 3 scans")
            print(f"  • Suspicious: 2 scans")
            print(f"  • Malicious: 3 scans")
            print("\n🎉 You can now generate reports with actual data!")
            
        except Exception as e:
            print(f"❌ Error adding test scans: {e}")
            await db.rollback()
            raise


if __name__ == "__main__":
    print("Adding test scan data to database...")
    asyncio.run(add_test_scans())
