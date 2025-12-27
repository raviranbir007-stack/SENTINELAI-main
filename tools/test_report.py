import asyncio
from server.app.core.report_generator import report_generator

sample = {
    "input": "example.com",
    "input_type": "url",
    "verdict": "clean",
    "confidence": 1.0,
    "threat_indicators": [],
    "api_results": {"apis_called": ["VirusTotal", "URLScan.io"]},
    "timestamp": "2025-12-27T00:00:00",
}

async def run():
    pdf = await report_generator.generate_analysis_report(sample)
    if pdf:
        print('PDF generated, bytes=', len(pdf))
    else:
        print('PDF generation returned None')

asyncio.run(run())
