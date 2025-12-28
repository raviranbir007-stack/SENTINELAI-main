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
  }

  /**
   * Setup all event listeners
   */
  setupEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-btn').forEach(btn => {
      btn.addEventListener('click', (e) => this.switchSection(e.target.dataset.section));
    });

    // File upload
    const fileUploadArea = document.getElementById('file-upload-area');
    const fileInput = document.getElementById('file-input');
    
    fileUploadArea.addEventListener('click', () => fileInput.click());
    fileUploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      fileUploadArea.style.borderColor = 'var(--accent-color)';
    });
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

      this.showLoading(false);
    } catch (error) {
      console.error('Error loading dashboard:', error);
      this.showLoading(false);
    }
  }

  /**
   * Update dashboard stats
   */
  updateDashboardStats(stats) {
    // Use mock data if API doesn't provide stats
    const mockStats = {
      critical_threats: Math.floor(Math.random() * 5),
      medium_threats: Math.floor(Math.random() * 12),
      low_threats: Math.floor(Math.random() * 20),
      files_scanned: 156,
    };

    const finalStats = stats && stats.critical_threats ? stats : mockStats;

    document.getElementById('stat-critical').textContent = finalStats.critical_threats || 0;
    document.getElementById('stat-medium').textContent = finalStats.medium_threats || 0;
    document.getElementById('stat-low').textContent = finalStats.low_threats || 0;
    document.getElementById('stat-files').textContent = finalStats.files_scanned || 0;
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
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('📱 DOM Ready - Starting Dashboard');
  window.dashboard = new Dashboard();
});
