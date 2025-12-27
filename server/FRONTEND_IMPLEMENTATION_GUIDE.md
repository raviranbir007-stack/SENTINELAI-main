# SENTINEL-AI Frontend Implementation Guide

## Overview
This guide documents the frontend features needed to display threats, generate reports, and filter by time range.

## Required Frontend Features

### 1. Threats Dashboard Page

#### Time Range Selector Component
```javascript
// Add clickable time range buttons
- 24 Hours (default)
- 7 Days
- 30 Days
- Custom Date Range (with date picker)

// API Call Example
fetch('/api/v1/threats?time_range=7d')
```

#### Threats Table Display
Display the following columns:
- **Threat ID**: THR001, THR002, etc.
- **Threat Type**: Process Injection, Malware, Phishing, Reconnaissance, etc.
- **Severity**: Critical (red), High (orange), Medium (yellow), Low (green)
- **Source IP**: 192.168.1.50
- **Location**: Bangalore, India
- **Detection Time**: YYYY-MM-DD HH:MM:SS
- **Status**: Active, Resolved, Mitigated, Quarantined
- **Actions**: View Details, Generate Report, Respond

#### Threat Detail Modal
When clicking "View Details" on a threat:
- Show comprehensive threat information
- Display all threat details from the API
- Show API detection results (Shodan, AbuseIPDB, VirusTotal, etc.)
- Show confidence score
- Provide "Generate Report" button

### 2. Reports Page

#### Report List View
Display all generated reports with:
- Report ID
- Associated Threat ID
- Report Title
- Generation Date/Time
- File Size
- Status (Completed, Generating, Failed)
- Download Button

#### Report Generation
```javascript
// API Endpoint to generate report
POST /api/v1/reports/generate?threat_id=THR001

// Response
{
  "report_id": "RPT001",
  "threat_id": "THR001",
  "status": "generated",
  "download_url": "/api/v1/reports/download/RPT001"
}
```

#### PDF Download
```javascript
// Download generated report
GET /api/v1/reports/download/RPT001

// This returns a PDF file with:
// - Threat metadata
// - AI-powered analysis from Gemini
// - API findings summary
// - Security recommendations
// - Professional formatting with tables and styling
```

### 3. Dashboard Updates

#### Summary Card
Add time range selector to show:
- Total Scans (varies by time range)
- Threats Detected (varies by time range)
- Critical Threats Count
- System Status

#### Statistics Widget
```javascript
// Fetch stats for selected time range
GET /api/v1/dashboard/stats?time_range=7d

// Returns threat count breakdown by severity
```

### 4. API Endpoints Required

#### Threats Endpoints
```
GET /api/v1/threats?time_range=24h|7d|30d|custom&start_date=YYYY-MM-DD&end_date=YYYY-MM-DD
  Returns: List of threats filtered by time range

GET /api/v1/threats/{threat_id}
  Returns: Detailed threat information with API results

POST /api/v1/threats/{threat_id}/respond
  Returns: Confirmation of threat response action

POST /api/v1/threats/scan-ip
  Body: { "ip_address": "192.168.1.50" }
  Returns: IP scan results from multiple APIs
```

#### Reports Endpoints
```
GET /api/v1/reports?time_range=24h&threat_id=THR001
  Returns: List of generated reports

POST /api/v1/reports/generate?threat_id=THR001
  Returns: Generated report metadata

GET /api/v1/reports/download/{report_id}
  Returns: PDF file download
```

#### Dashboard Endpoints
```
GET /api/v1/dashboard/summary?time_range=24h|7d|30d
  Returns: Summary statistics for selected time range

GET /api/v1/dashboard/threats?time_range=24h&severity=critical
  Returns: Threats list with optional severity filter

GET /api/v1/dashboard/stats?time_range=24h|7d|30d
  Returns: Detailed statistics breakdown
```

## UI Components to Implement

### 1. Time Range Selector
```html
<div class="time-range-selector">
  <button class="btn" data-range="24h">24 Hours</button>
  <button class="btn" data-range="7d">7 Days</button>
  <button class="btn" data-range="30d">30 Days</button>
  <button class="btn" data-range="custom">Custom Range</button>
</div>

<!-- Custom date range picker -->
<div class="custom-date-picker" style="display: none;">
  <input type="date" id="start_date" />
  <input type="date" id="end_date" />
  <button onclick="filterThreats()">Apply Filter</button>
</div>
```

### 2. Threats Table
```html
<table class="threats-table">
  <thead>
    <tr>
      <th>Threat ID</th>
      <th>Type</th>
      <th>Severity</th>
      <th>Source</th>
      <th>Location</th>
      <th>Detection Time</th>
      <th>Status</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody id="threats-body">
    <!-- Populated by JavaScript -->
  </tbody>
</table>
```

### 3. Report Download Button
```html
<button onclick="downloadReport('RPT001')" class="btn btn-primary">
  📥 Download PDF
</button>
```

## JavaScript Implementation Example

```javascript
// Fetch threats with time range
async function fetchThreats(timeRange = '24h') {
  try {
    const response = await fetch(`/api/v1/threats?time_range=${timeRange}`);
    const data = await response.json();
    displayThreats(data.threats);
  } catch (error) {
    console.error('Error fetching threats:', error);
  }
}

// Generate and download report
async function generateAndDownloadReport(threatId) {
  try {
    // Generate report
    const genResponse = await fetch(`/api/v1/reports/generate?threat_id=${threatId}`, {
      method: 'POST'
    });
    const genData = await genResponse.json();
    const reportId = genData.report_id;
    
    // Download report
    window.location.href = `/api/v1/reports/download/${reportId}`;
  } catch (error) {
    console.error('Error generating report:', error);
  }
}

// Display threats in table
function displayThreats(threats) {
  const tbody = document.getElementById('threats-body');
  tbody.innerHTML = threats.map(threat => `
    <tr>
      <td>${threat.threat_id}</td>
      <td>${threat.type}</td>
      <td><span class="severity ${threat.severity}">${threat.severity}</span></td>
      <td>${threat.source}</td>
      <td>${threat.location}</td>
      <td>${new Date(threat.timestamp).toLocaleString()}</td>
      <td>${threat.status}</td>
      <td>
        <button onclick="viewThreatDetails('${threat.threat_id}')">Details</button>
        <button onclick="generateAndDownloadReport('${threat.threat_id}')">Report</button>
      </td>
    </tr>
  `).join('');
}

// View threat details in modal
async function viewThreatDetails(threatId) {
  try {
    const response = await fetch(`/api/v1/threats/${threatId}`);
    const threat = await response.json();
    
    // Display threat details in modal with all information
    showModal(threat);
  } catch (error) {
    console.error('Error fetching threat details:', error);
  }
}
```

## Styling Recommendations

### Severity Color Scheme
```css
.severity.critical { background: #D32F2F; color: white; padding: 4px 8px; border-radius: 3px; }
.severity.high    { background: #F57C00; color: white; padding: 4px 8px; border-radius: 3px; }
.severity.medium  { background: #FBC02D; color: black; padding: 4px 8px; border-radius: 3px; }
.severity.low     { background: #388E3C; color: white; padding: 4px 8px; border-radius: 3px; }
```

### Status Badge Colors
```css
.status.active     { background: #1976D2; color: white; }
.status.resolved   { background: #388E3C; color: white; }
.status.mitigated  { background: #FBC02D; color: black; }
.status.quarantined{ background: #D32F2F; color: white; }
```

## Data Flow for Attack Scenario (Kali → Victim)

1. **Attacker initiates attack from Kali Linux**
2. **Victim's SENTINEL-AI detects the attack**
3. **Threat is recorded with:**
   - Source IP (attacker's Kali IP)
   - Attack Type (Process Injection, Network Scan, etc.)
   - Target Ports/Services
   - Location data (if available)
4. **Threat is displayed in Dashboard/Threats Page**
5. **User can:**
   - View detailed threat information
   - Generate comprehensive AI-powered PDF report
   - See API analysis from Shodan, VirusTotal, AbuseIPDB
   - Filter threats by time range
   - Download report for documentation/analysis

## PDF Report Contents

The generated PDF report includes:
1. Report metadata (ID, generated date, threat classification)
2. Threat details (source, target, detection time, severity)
3. AI-powered analysis powered by Gemini API
4. Security API findings from:
   - AbuseIPDB
   - Shodan
   - VirusTotal
   - URLScan
   - Hybrid Analysis
5. Professional recommendations for threat remediation
6. Conclusion with severity assessment

## Browser Compatibility
- Chrome/Chromium: ✓
- Firefox: ✓
- Safari: ✓
- Edge: ✓

## Required Dependencies
- Frontend framework (React, Vue, or vanilla JS)
- Chart library for statistics (optional)
- PDF library for client-side PDF generation (optional)
- Date picker library for custom date range selection (optional)
