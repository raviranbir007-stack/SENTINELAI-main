/**
 * SENTINEL-AI Dashboard JavaScript
 * Manages dashboard interactions and API communication
 */

class Dashboard {
  constructor() {
    this.api = api;
    this.currentSection = 'dashboard';
    this.selectedFile = null;
    this.autoRefreshInterval = null;
    this.init();
  }

  /**
   * Initialize dashboard
   */
  init() {
    console.log('🚀 SENTINEL-AI Dashboard Initializing...');
    this.setupEventListeners();
    this.checkAPIHealth();
    this.loadDashboardData();

    // Add Deep Manual Scan and Harden Now buttons if not present
    setTimeout(() => {
      this.addSecurityControls();
    }, 500);
  }

  /**
   * Add Deep Manual Scan and Harden Now buttons to dashboard
   */
  addSecurityControls() {
    const dashboardSection = document.getElementById('dashboard-section');
    if (!dashboardSection) return;
    if (document.getElementById('deep-manual-scan-btn')) return; // Already added

    const controlsDiv = document.createElement('div');
    controlsDiv.style.cssText = 'display:flex;gap:1.5rem;margin-bottom:1.5rem;';
    controlsDiv.innerHTML = `
      <button id="deep-manual-scan-btn" style="background:var(--primary);color:white;padding:0.75rem 1.5rem;border:none;border-radius:4px;font-size:1rem;cursor:pointer;">Deep Manual Scan</button>
      <button id="harden-now-btn" style="background:var(--success);color:white;padding:0.75rem 1.5rem;border:none;border-radius:4px;font-size:1rem;cursor:pointer;">Harden Now</button>
    `;
    dashboardSection.prepend(controlsDiv);

    document.getElementById('deep-manual-scan-btn').onclick = () => this.showDeepScanModal();
    document.getElementById('harden-now-btn').onclick = () => this.hardenNow();
  }

  /**
   * Show modal for deep manual scan input and results
   */
  showDeepScanModal() {
    // Remove any existing modal
    document.getElementById('deep-scan-modal')?.remove();
    const modal = document.createElement('div');
    modal.id = 'deep-scan-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:10000;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML = `
      <div style="background:white;max-width:500px;width:100%;border-radius:8px;padding:2rem;box-shadow:0 8px 32px rgba(0,0,0,0.25);position:relative;">
        <button onclick="document.getElementById('deep-scan-modal').remove()" style="position:absolute;top:1rem;right:1rem;background:none;border:none;font-size:2rem;cursor:pointer;">&times;</button>
        <h2 style="margin-top:0;">Deep Manual Scan</h2>
        <input id="deep-scan-input" type="text" placeholder="Enter IP, URL, domain, or file hash" style="width:100%;padding:0.75rem;margin-bottom:1rem;font-size:1rem;border-radius:4px;border:1px solid var(--border);">
        <button id="deep-scan-submit" style="background:var(--primary);color:white;padding:0.75rem 1.5rem;border:none;border-radius:4px;font-size:1rem;cursor:pointer;width:100%;">Start Deep Scan</button>
        <div id="deep-scan-result" style="margin-top:1.5rem;"></div>
      </div>
    `;
    document.body.appendChild(modal);
    document.getElementById('deep-scan-submit').onclick = () => this.runDeepManualScan();
  }

  /**
   * Run deep manual scan and show results
   */
  async runDeepManualScan() {
    const input = document.getElementById('deep-scan-input').value.trim();
    const resultDiv = document.getElementById('deep-scan-result');
    if (!input) {
      resultDiv.innerHTML = '<span style="color:var(--destructive);">Please enter a valid target.</span>';
      return;
    }
    resultDiv.innerHTML = 'Scanning... <span class="spinner"></span>';
    try {
      // Use universal scan endpoint with external APIs forced
      const resp = await fetch('/api/v1/scan/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: input, include_external_apis: true, scan_source: 'manual' })
      });
      const data = await resp.json();
      if (data && data.verdict) {
        resultDiv.innerHTML = `<strong>Result:</strong> ${data.verdict}<br><pre style="white-space:pre-wrap;font-size:0.95rem;">${JSON.stringify(data, null, 2)}</pre>`;
      } else {
        resultDiv.innerHTML = '<span style="color:var(--destructive);">No result or scan failed.</span>';
      }
    } catch (e) {
      resultDiv.innerHTML = `<span style="color:var(--destructive);">Scan error: ${e.message || e}</span>`;
    }
  }

  /**
   * Harden system now (calls backend endpoint)
   */
  async hardenNow() {
    this.showLoading(true, 'Applying security hardening...');
    try {
      const resp = await fetch('/api/v1/dashboard/harden-now', { method: 'POST' });
      const data = await resp.json();
      this.showLoading(false);
      this.showToast(data?.message || 'Hardening attempted. Please re-scan to verify.', data?.success ? 'success' : 'warning');
      this.loadDashboardData();
    } catch (e) {
      this.showLoading(false);
      this.showToast('Failed to harden system: ' + (e.message || e), 'error');
    }
  }

  /**
   * Setup all event listeners
   */
  setupEventListeners() {
          this.api.getSecurityPosture ? this.api.getSecurityPosture() : fetch('/api/v1/dashboard/security-posture').then(r => r.json()),
    // Navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', (e) => this.switchSection(e.target.dataset.section));
    });

    // File upload
    const fileUploadArea = document.getElementById('file-upload-area');

        // Show posture warning if needed
        this.showSecurityPostureWarning(posture);
    const fileInput = document.getElementById('file-input');
    
    fileUploadArea.addEventListener('click', () => fileInput.click());
    fileUploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      fileUploadArea.style.borderColor = 'var(--accent-color)';
    });

    /**
     * Show security posture warning banner/button
     */
    showSecurityPostureWarning(posture) {
      // Remove any existing banner
      const oldBanner = document.getElementById('security-posture-warning');
      if (oldBanner) oldBanner.remove();

      if (!posture || !posture.summary) return;
      const { critical_findings, high_findings } = posture.summary;
      if (critical_findings > 0 || high_findings > 0) {
        // Insert banner at top of dashboard
        const banner = document.createElement('div');
        banner.id = 'security-posture-warning';
        banner.style.cssText = 'background:var(--warning);color:black;padding:1rem 2rem;margin-bottom:1rem;border-radius:6px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 8px rgba(0,0,0,0.08);font-weight:500;';
        banner.innerHTML = `
          <span>⚠️ Security Posture Warning: ${critical_findings} Critical, ${high_findings} High findings detected. <button id="view-posture-details" style="margin-left:1.5rem;background:var(--destructive);color:white;border:none;padding:0.5rem 1rem;border-radius:4px;cursor:pointer;">View & Fix</button></span>
        `;
        const dashboardSection = document.getElementById('dashboard-section');
        if (dashboardSection) dashboardSection.prepend(banner);
        document.getElementById('view-posture-details').onclick = () => this.showPostureDetails(posture);
      }
    }

    /**
     * Show posture details and remediation modal
     */
    showPostureDetails(posture) {
      // Remove any existing modal
      const oldModal = document.getElementById('posture-modal');
      if (oldModal) oldModal.remove();

      const findings = posture.report?.findings || {};
      let findingsList = '';
      for (const [cat, items] of Object.entries(findings)) {
        if (!Array.isArray(items) || items.length === 0) continue;
        findingsList += `<h4 style="margin-top:1.5rem;">${cat.charAt(0).toUpperCase() + cat.slice(1)}</h4><ul style="margin-bottom:1rem;">`;
        for (const item of items) {
          findingsList += `<li style="margin-bottom:0.5rem;"><strong>${item.title || item.name}</strong>: ${item.description || ''} <br><em>Severity: ${item.severity || ''}</em>${item.remediation ? `<br><span style='color:var(--primary);'>Fix: ${item.remediation}</span>` : ''}</li>`;
        }
        findingsList += '</ul>';
      }
      if (!findingsList) findingsList = '<div style="color:var(--muted-foreground);">No detailed findings available.</div>';

      // Modal HTML
      const modal = document.createElement('div');
      modal.id = 'posture-modal';
      modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:10000;display:flex;align-items:center;justify-content:center;';
      modal.innerHTML = `
        <div style="background:white;max-width:700px;width:100%;border-radius:8px;padding:2rem;box-shadow:0 8px 32px rgba(0,0,0,0.25);position:relative;">
          <button onclick="document.getElementById('posture-modal').remove()" style="position:absolute;top:1rem;right:1rem;background:none;border:none;font-size:2rem;cursor:pointer;">&times;</button>
          <h2 style="margin-top:0;">Security Posture Details</h2>
          <div>${findingsList}</div>
          <div style="margin-top:2rem;text-align:right;">
            <button id="fix-all-posture-btn" style="background:var(--success);color:white;border:none;padding:0.75rem 1.5rem;border-radius:4px;cursor:pointer;font-size:1rem;">Fix All Automatically</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
      document.getElementById('fix-all-posture-btn').onclick = () => this.fixAllPostureFindings();
    }

    /**
     * Attempt to fix all posture findings (calls backend or shows instructions)
     */
    async fixAllPostureFindings() {
      try {
        this.showLoading(true, 'Attempting to fix all posture issues...');
        // Try to call backend endpoint for auto-remediation if available
        const resp = await (this.api.fixSecurityPosture ? this.api.fixSecurityPosture() : fetch('/api/v1/dashboard/fix-security-posture', {method:'POST'}).then(r => r.json()));
        this.showLoading(false);
        this.showToast(resp?.message || 'Remediation attempted. Please re-scan to verify.', resp?.success ? 'success' : 'warning');
        document.getElementById('posture-modal')?.remove();
        this.loadDashboardData();
      } catch (e) {
        this.showLoading(false);
        this.showToast('Failed to fix posture issues: ' + (e.message || e), 'error');
      }
    }
    fileUploadArea.addEventListener('dragleave', () => {
      fileUploadArea.style.borderColor = 'var(--border-color)';
    });
    fileUploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      fileUploadArea.style.borderColor = 'var(--border-color)';
      const files = e.dataTransfer.files;
      if (files.length) {
        this.handleFileSelect(files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length) {
        this.handleFileSelect(e.target.files[0]);
      }
    });

    // Scan buttons
    document.getElementById('scan-file-btn').addEventListener('click', () => this.scanFile());
    document.getElementById('scan-url-btn').addEventListener('click', () => this.scanURL());
    document.getElementById('scan-ip-btn').addEventListener('click', () => this.scanIP());

    // Threat filters
    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', (e) => this.filterThreats(e.target.dataset.filter));
    });

    // Time range filters
    document.querySelectorAll('.time-buttons button').forEach(btn => {
      btn.addEventListener('click', (e) => this.handleTimeRangeChange(e.target));
    });

    // Notification button
    const notificationBtn = document.querySelector('.icon-btn:has(.notification-badge)');
    if (notificationBtn) {
      notificationBtn.addEventListener('click', () => this.showNotifications());
    }

    // Settings
    document.getElementById('test-connection-btn').addEventListener('click', () => this.testConnection());
    document.getElementById('auto-refresh').addEventListener('change', (e) => this.toggleAutoRefresh(e.target.checked));
  }

  /**
   * Switch between dashboard sections
   */
  switchSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    
    // Remove active class from nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    
    // Show selected section
    document.getElementById(`${sectionName}-section`).classList.add('active');
    
    // Highlight active nav button
    document.querySelector(`[data-section="${sectionName}"]`).classList.add('active');
    
    this.currentSection = sectionName;

    // Load data for section
    if (sectionName === 'threats') {
      this.loadThreatsFullList();
    }
  }

  /**
   * Check API health
   */
  async checkAPIHealth() {
    try {
      const response = await this.api.health();
      this.updateAPIStatus(true);
      console.log('✅ API Health: OK', response);
    } catch (error) {
      this.updateAPIStatus(false);
      console.error('❌ API Health: FAILED', error);
    }
  }

  /**
   * Update API status indicator
   */
  updateAPIStatus(isConnected) {
    const statusIndicator = document.getElementById('api-status');
    if (isConnected) {
      statusIndicator.classList.remove('loading', 'disconnected');
      statusIndicator.classList.add('connected');
      statusIndicator.textContent = 'Connected';
    } else {
      statusIndicator.classList.remove('loading', 'connected');
      statusIndicator.classList.add('disconnected');
      statusIndicator.textContent = 'Disconnected';
    }
  }

  /**
   * Load dashboard data
   */
  async loadDashboardData() {
    try {
      this.showLoading(true, 'Loading dashboard...');

      const [summary, threats, stats] = await Promise.all([
        this.api.getDashboardSummary(),
        this.api.getDashboardThreats(),
        this.api.getDashboardStats(),
      ]);

      console.log('📊 Dashboard Data:', { summary, threats, stats });

      this.updateDashboardStats(stats);
      this.updateThreatsDisplay(threats);
      this.updateNotificationBadge();

      this.showLoading(false);
    } catch (error) {
      console.error('Error loading dashboard:', error);
      this.showLoading(false);
    }
  }

  /**
   * Update dashboard stats
   */
  updateDashboardStats(statsOrScans) {
    // If array is passed, use it as scans; otherwise use localStorage
    const storedScans = Array.isArray(statsOrScans) ? statsOrScans : JSON.parse(localStorage.getItem('recentScans') || '[]');
    
    // Calculate real stats from scans
    const criticalCount = storedScans.filter(s => s.threat_level === 'malicious' || s.threat_level === 'critical').length;
    const highCount = storedScans.filter(s => s.threat_level === 'suspicious' || s.threat_level === 'high').length;
    const mediumCount = storedScans.filter(s => s.threat_level === 'medium').length;
    const lowCount = storedScans.filter(s => s.threat_level === 'clean' || s.threat_level === 'low' || s.threat_level === 'safe').length;
    
    const finalStats = {
      critical_threats: statsOrScans?.critical_threats || criticalCount,
      medium_threats: statsOrScans?.medium_threats || (highCount + mediumCount),
      low_threats: statsOrScans?.low_threats || lowCount,
      files_scanned: storedScans.length || 0,
    };

    document.getElementById('stat-critical').textContent = finalStats.critical_threats;
    document.getElementById('stat-medium').textContent = finalStats.medium_threats;
    document.getElementById('stat-low').textContent = finalStats.low_threats;
    document.getElementById('stat-files').textContent = finalStats.files_scanned;
  }

  /**
   * Update threats display
   */
  updateThreatsDisplay(threats) {
    const threatsList = document.getElementById('threats-list');
    
    const mockThreats = [
      {
        id: 1,
        name: 'Suspicious Process Activity',
        details: 'Process_monitor.exe attempting network connection',
        severity: 'critical',
        timestamp: new Date(Date.now() - 3600000).toLocaleString(),
      },
      {
        id: 2,
        name: 'Malware Signature Detected',
        details: 'file_download.exe matches known malware pattern',
        severity: 'critical',
        timestamp: new Date(Date.now() - 7200000).toLocaleString(),
      },
      {
        id: 3,
        name: 'Suspicious URL Access',
        details: 'Attempted access to known phishing domain',
        severity: 'medium',
        timestamp: new Date(Date.now() - 10800000).toLocaleString(),
      },
    ];

    const threatsData = threats && threats.length > 0 ? threats : mockThreats;

    threatsList.innerHTML = threatsData.map(threat => `
      <div class="threat-item severity-${threat.severity}">
        <div class="threat-info">
          <div class="threat-name">${threat.name}</div>
          <div class="threat-details">${threat.details}</div>
        </div>
        <div class="threat-severity ${threat.severity}">${threat.severity}</div>
      </div>
    `).join('');
  }

  /**
   * Load full threats list
   */
  async loadThreatsFullList() {
    try {
      this.showLoading(true, 'Loading threats...');
      const threats = await this.api.getThreats();
      console.log('🔍 All Threats:', threats);
      
      // Display threats in a modal or dedicated section
      const threatsModal = document.createElement('div');
      threatsModal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);z-index:1000;display:flex;align-items:center;justify-content:center;padding:2rem;';
      threatsModal.innerHTML = `
        <div style="background:var(--card);border-radius:8px;max-width:1200px;width:100%;max-height:90vh;overflow-y:auto;padding:2rem;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
            <h2>All Detected Threats & Scans</h2>
            <button onclick="this.closest('[style*=fixed]').remove()" style="background:var(--destructive);color:white;border:none;padding:0.5rem 1rem;border-radius:4px;cursor:pointer;">Close</button>
          </div>
          <div style="margin-bottom:1rem;color:var(--muted-foreground);">
            Total: ${threats.total_threats} | Range: ${threats.time_range}
          </div>
          <div style="display:grid;gap:1rem;">
            ${threats.threats.map(threat => `
              <div style="background:var(--secondary);padding:1rem;border-radius:6px;border-left:3px solid ${
                threat.severity === 'critical' ? 'var(--destructive)' :
                threat.severity === 'high' ? 'var(--warning)' : 
                threat.severity === 'medium' ? 'var(--primary)' : 'var(--success)'
              }">
                <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:0.5rem;">
                  <div>
                    <strong style="font-size:1.1rem;">${threat.name}</strong>
                    <div style="color:var(--muted-foreground);font-size:0.9rem;">
                      ${threat.type} | ${threat.detected_by}
                    </div>
                  </div>
                  <span style="background:${
                    threat.severity === 'critical' ? 'var(--destructive)' :
                    threat.severity === 'high' ? 'var(--warning)' : 
                    threat.severity === 'medium' ? 'var(--primary)' : 'var(--success)'
                  };color:white;padding:0.25rem 0.75rem;border-radius:12px;font-size:0.85rem;text-transform:uppercase;">
                    ${threat.severity}
                  </span>
                </div>
                <div style="margin:0.5rem 0;color:var(--foreground);">${threat.details}</div>
                <div style="display:flex;gap:1rem;flex-wrap:wrap;font-size:0.9rem;color:var(--muted-foreground);">
                  <span>📍 ${threat.location || threat.source}</span>
                  <span>🕐 ${new Date(threat.timestamp).toLocaleString()}</span>
                  <span>Status: ${threat.status}</span>
                  ${threat.confidence ? `<span>Confidence: ${(threat.confidence * 100).toFixed(1)}%</span>` : ''}
                </div>
                ${threat.report_url ? `
                  <div style="margin-top:0.75rem;">
                    <a href="${threat.report_url}" target="_blank" style="background:var(--primary);color:var(--primary-foreground);padding:0.5rem 1rem;border-radius:4px;text-decoration:none;display:inline-block;font-size:0.9rem;">
                      📄 Download Report
                    </a>
                  </div>
                ` : ''}
              </div>
            `).join('')}
          </div>
        </div>
      `;
      document.body.appendChild(threatsModal);
      
      this.showLoading(false);
    } catch (error) {
      console.error('Error loading threats:', error);
      this.showLoading(false);
    }
  }

  /**
   * Filter threats
   */
  filterThreats(filter) {
    // Update filter button styles
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-filter="${filter}"]`).classList.add('active');

    // In a real app, would filter the displayed threats
    console.log('🔎 Filtering threats by:', filter);
  }

  /**
   * Handle file selection
   */
  handleFileSelect(file) {
    this.selectedFile = file;
    const fileUploadArea = document.getElementById('file-upload-area');
    fileUploadArea.innerHTML = `
      <p>✓ File selected: <strong>${file.name}</strong></p>
      <p style="font-size: 0.9rem; color: var(--text-secondary); margin-top: 0.5rem;">
        Size: ${(file.size / 1024).toFixed(2)} KB
      </p>
    `;
    document.getElementById('scan-file-btn').disabled = false;
  }

  /**
   * Scan file
   */
  async scanFile() {
    if (!this.selectedFile) {
      alert('Please select a file first');
      return;
    }

    try {
      this.showLoading(true, 'Scanning file...');
      const result = await this.api.scanFile(this.selectedFile);
      console.log('📄 File Scan Result:', result);

      // Store scan result for stats
      this.storeScanInLocalStorage({
        type: 'file',
        target: this.selectedFile.name,
        threat_level: result.threat_level,
        timestamp: new Date().toISOString(),
        report_url: result.report_url
      });

      // Refresh stats
      this.loadDashboardData();

      const resultDiv = document.getElementById('file-scan-result');
      const threatLevel = result.threat_level || result.analysis?.verdict || 'unknown';
      const isSafe = threatLevel === 'safe' || threatLevel === 'clean';
      const threats = result.threats_detected || 0;
      
      resultDiv.className = isSafe ? 'scan-result success' : 'scan-result error';
      resultDiv.innerHTML = `
        <strong>${isSafe ? '✓' : '⚠'} Scan Complete</strong><br>
        File: ${this.selectedFile.name}<br>
        Hash: ${result.file_hash || 'N/A'}<br>
        Threat Level: ${threatLevel}<br>
        Threats Detected: ${threats}<br>
        Confidence: ${(result.confidence * 100).toFixed(1)}%<br>
        <small>Scanned at: ${new Date().toLocaleTimeString()}</small>
        ${result.report_url ? `<br><br><a href="${result.report_url}" target="_blank" style="color: var(--primary); text-decoration: none;">📄 Download Report</a>` : ''}
      `;

      this.showLoading(false);
      this.selectedFile = null;
      document.getElementById('file-input').value = '';
    } catch (error) {
      console.error('File scan error:', error);
      const resultDiv = document.getElementById('file-scan-result');
      resultDiv.className = 'scan-result error';
      resultDiv.textContent = `Error: ${error.message}`;
      this.showLoading(false);
    }
  }

  /**
   * Scan URL
   */
  async scanURL() {
    const url = document.getElementById('url-input').value.trim();
    
    if (!url) {
      alert('Please enter a URL');
      return;
    }

    try {
      this.showLoading(true, 'Scanning URL...');
      const result = await this.api.scanUrl(url);
      console.log('🌐 URL Scan Result:', result);

      // Store scan result for stats
      this.storeScanInLocalStorage({
        type: 'url',
        target: url,
        threat_level: result.threat_level,
        timestamp: new Date().toISOString(),
        report_url: result.report_url
      });

      // Refresh stats
      this.loadDashboardData();

      const resultDiv = document.getElementById('url-scan-result');
      const threatLevel = result.threat_level || result.analysis?.verdict || 'unknown';
      const isSafe = threatLevel === 'safe' || threatLevel === 'clean';
      
      resultDiv.className = isSafe ? 'scan-result success' : 'scan-result error';
      resultDiv.innerHTML = `
        <strong>${isSafe ? '✓' : '⚠'} Scan Complete</strong><br>
        URL: ${url}<br>
        Threat Level: ${threatLevel}<br>
        Confidence: ${(result.confidence * 100).toFixed(1)}%<br>
        <small>Scanned at: ${new Date().toLocaleTimeString()}</small>
        ${result.report_url ? `<br><br><a href="${result.report_url}" target="_blank" style="color: var(--primary); text-decoration: none;">📄 Download Report</a>` : ''}
      `;

      this.showLoading(false);
    } catch (error) {
      console.error('URL scan error:', error);
      const resultDiv = document.getElementById('url-scan-result');
      resultDiv.className = 'scan-result error';
      resultDiv.textContent = `Error: ${error.message}`;
      this.showLoading(false);
    }
  }

  /**
   * Scan IP address
   */
  async scanIP() {
    const ip = document.getElementById('ip-input').value.trim();
    
    if (!ip) {
      alert('Please enter an IP address');
      return;
    }

    try {
      this.showLoading(true, 'Scanning IP...');
      const result = await this.api.scanIP(ip);
      console.log('🔗 IP Scan Result:', result);

      // Store scan result for stats
      this.storeScanInLocalStorage({
        type: 'ip',
        target: ip,
        threat_level: result.threat_level,
        timestamp: new Date().toISOString(),
        report_url: result.report_url
      });

      // Refresh stats
      this.loadDashboardData();

      const resultDiv = document.getElementById('ip-scan-result');
      const threatLevel = result.threat_level || result.analysis?.verdict || 'unknown';
      const isSafe = threatLevel === 'safe' || threatLevel === 'clean';
      const threats = result.threats_detected || 0;
      
      resultDiv.className = isSafe ? 'scan-result success' : 'scan-result error';
      resultDiv.innerHTML = `
        <strong>${isSafe ? '✓' : '⚠'} Scan Complete</strong><br>
        IP Address: ${ip}<br>
        Threat Level: ${threatLevel}<br>
        Threats Detected: ${threats}<br>
        Confidence: ${(result.confidence * 100).toFixed(1)}%<br>
        <small>Scanned at: ${new Date().toLocaleTimeString()}</small>
        ${result.report_url ? `<br><br><a href="${result.report_url}" target="_blank" style="color: var(--primary); text-decoration: none;">📄 Download Report</a>` : ''}
      `;

      this.showLoading(false);
    } catch (error) {
      console.error('IP scan error:', error);
      const resultDiv = document.getElementById('ip-scan-result');
      resultDiv.className = 'scan-result error';
      resultDiv.textContent = `Error: ${error.message}`;
      this.showLoading(false);
    }
  }

  /**
   * Store scan result in local storage
   */
  storeScanInLocalStorage(scan) {
    try {
      const scans = JSON.parse(localStorage.getItem('recentScans') || '[]');
      scans.unshift(scan);
      // Keep only last 100 scans
      if (scans.length > 100) scans.pop();
      localStorage.setItem('recentScans', JSON.stringify(scans));
    } catch (e) {
      console.error('Error storing scan:', e);
    }
  }

  /**
   * Test API connection
   */
  async testConnection() {
    try {
      this.showLoading(true, 'Testing connection...');
      await this.api.health();
      
      const resultDiv = document.getElementById('connection-result');
      resultDiv.className = 'connection-result success';
      resultDiv.innerHTML = `
        <strong>✓ Connection Successful</strong><br>
        Backend API is responding correctly<br>
        <small>Tested at: ${new Date().toLocaleTimeString()}</small>
      `;

      this.showLoading(false);
    } catch (error) {
      console.error('Connection test error:', error);
      const resultDiv = document.getElementById('connection-result');
      resultDiv.className = 'connection-result error';
      resultDiv.innerHTML = `
        <strong>✗ Connection Failed</strong><br>
        Error: ${error.message}<br>
        Make sure the FastAPI backend is running
      `;
      this.showLoading(false);
    }
  }

  /**
   * Toggle auto-refresh
   */
  toggleAutoRefresh(enabled) {
    if (this.autoRefreshInterval) {
      clearInterval(this.autoRefreshInterval);
      this.autoRefreshInterval = null;
    }

    if (enabled) {
      this.autoRefreshInterval = setInterval(() => {
        if (this.currentSection === 'dashboard') {
          console.log('🔄 Auto-refreshing dashboard...');
          this.loadDashboardData();
        }
      }, 30000); // 30 seconds
      console.log('✓ Auto-refresh enabled');
    } else {
      console.log('✗ Auto-refresh disabled');
    }
  }

  /**
   * Show/hide loading modal
   */
  showLoading(show, message = 'Loading...') {
    const modal = document.getElementById('loading-modal');
    const text = document.getElementById('loading-text');
    
    if (show) {
      modal.classList.remove('hidden');
      text.textContent = message;
    } else {
      modal.classList.add('hidden');
    }
  }

  /**
   * Handle time range filter change
   */
  handleTimeRangeChange(btn) {
    // Remove active class from all time buttons
    btn.parentElement.querySelectorAll('button').forEach(b => {
      b.classList.remove('btn-secondary');
      b.classList.add('btn-outline');
    });
    
    // Set clicked button as active
    btn.classList.remove('btn-outline');
    btn.classList.add('btn-secondary');
    
    const timeRange = btn.textContent.trim();
    console.log(`📅 Time range changed to: ${timeRange}`);
    
    // Store selected time range
    localStorage.setItem('selectedTimeRange', timeRange);
    
    // Filter scans based on time range
    this.filterScansByTimeRange(timeRange);
    
    // Show toast notification
    this.showToast(`Time range set to ${timeRange}`, 'info');
  }

  /**
   * Filter scans by time range
   */
  filterScansByTimeRange(timeRange) {
    const scans = JSON.parse(localStorage.getItem('recentScans') || '[]');
    const now = new Date();
    let filteredScans = scans;
    
    // Calculate time threshold
    let hoursAgo = 24; // Default 24h
    if (timeRange === '7 days') hoursAgo = 24 * 7;
    else if (timeRange === '30 days') hoursAgo = 24 * 30;
    else if (timeRange !== '24h' && timeRange !== 'Custom') hoursAgo = 24;
    
    const threshold = new Date(now.getTime() - hoursAgo * 60 * 60 * 1000);
    
    // Filter scans within time range
    filteredScans = scans.filter(scan => {
      const scanDate = new Date(scan.timestamp);
      return scanDate >= threshold;
    });
    
    console.log(`📊 Filtered ${filteredScans.length} scans from last ${timeRange}`);
    
    // Update stats with filtered data
    this.updateDashboardStats(filteredScans);
  }

  /**
   * Show notifications panel
   */
  showNotifications() {
    const scans = JSON.parse(localStorage.getItem('recentScans') || '[]');
    const recentScans = scans.slice(0, 10);
    
    let notificationsHTML = `
      <div style="position: fixed; top: 70px; right: 20px; width: 400px; max-height: 500px; 
                  background: var(--card); border: 1px solid var(--border); border-radius: 8px;
                  box-shadow: 0 10px 40px rgba(0,0,0,0.5); z-index: 1000; overflow-y: auto;">
        <div style="padding: 1rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
          <h3 style="margin: 0; font-size: 1rem;">Recent Scans</h3>
          <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: var(--foreground); cursor: pointer; font-size: 1.5rem;">&times;</button>
        </div>
        <div style="padding: 0.5rem;">
    `;
    
    if (recentScans.length === 0) {
      notificationsHTML += `
        <div style="padding: 2rem; text-align: center; color: var(--muted-foreground);">
          No recent scans
        </div>
      `;
    } else {
      recentScans.forEach(scan => {
        const time = new Date(scan.timestamp).toLocaleString();
        const icon = scan.threat_level === 'malicious' ? '🔴' : scan.threat_level === 'suspicious' ? '🟡' : '🟢';
        
        notificationsHTML += `
          <div style="padding: 0.75rem; border-bottom: 1px solid var(--border); cursor: pointer;"
               onmouseover="this.style.background='var(--muted)'" 
               onmouseout="this.style.background='transparent'"
               onclick="${scan.report_url ? `window.open('${scan.report_url}', '_blank')` : ''}">
            <div style="display: flex; align-items: center; gap: 0.5rem;">
              <span style="font-size: 1.2rem;">${icon}</span>
              <div style="flex: 1;">
                <div style="font-weight: 500; font-size: 0.9rem;">${scan.type.toUpperCase()}: ${scan.target}</div>
                <div style="font-size: 0.75rem; color: var(--muted-foreground); margin-top: 0.25rem;">${time}</div>
              </div>
              ${scan.report_url ? '<span style="color: var(--primary);">📄</span>' : ''}
            </div>
          </div>
        `;
      });
    }
    
    notificationsHTML += `
        </div>
        <div style="padding: 0.75rem; border-top: 1px solid var(--border); text-align: center;">
          <button onclick="localStorage.removeItem('recentScans'); this.parentElement.parentElement.remove(); window.dashboard.loadDashboardData();" 
                  style="background: none; border: 1px solid var(--border); color: var(--foreground); 
                         padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-size: 0.875rem;">
            Clear All
          </button>
        </div>
      </div>
    `;
    
    // Remove any existing notification panel
    const existing = document.querySelector('[data-notification-panel]');
    if (existing) existing.remove();
    
    // Add new notification panel
    const panel = document.createElement('div');
    panel.setAttribute('data-notification-panel', 'true');
    panel.innerHTML = notificationsHTML;
    document.body.appendChild(panel);
    
    // Update badge
    this.updateNotificationBadge();
  }

  /**
   * Update notification badge count
   */
  updateNotificationBadge() {
    const scans = JSON.parse(localStorage.getItem('recentScans') || '[]');
    const badge = document.querySelector('.notification-badge');
    if (badge) {
      const unreadCount = scans.length;
      badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
      badge.style.display = unreadCount > 0 ? 'flex' : 'none';
    }
  }

  /**
   * Show toast notification
   */
  showToast(message, type = 'info') {
    const colors = {
      info: 'var(--primary)',
      success: 'var(--success)',
      warning: 'var(--warning)',
      error: 'var(--destructive)'
    };
    
    const toast = document.createElement('div');
    toast.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: var(--card);
      border: 1px solid ${colors[type] || colors.info};
      border-left: 4px solid ${colors[type] || colors.info};
      padding: 1rem 1.5rem;
      border-radius: 4px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      z-index: 10000;
      animation: slideIn 0.3s ease;
      max-width: 300px;
    `;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
      toast.style.animation = 'slideOut 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('📱 DOM Ready - Starting Dashboard');
  window.dashboard = new Dashboard();
});
