/**
 * SENTINEL-AI API Service Layer
 * Handles all communication with the FastAPI backend
 */

// Dynamic API configuration - use same protocol and host as current page
const API_PROTOCOL = window.location.protocol;
const API_HOST = window.location.hostname;
const API_PORT = window.location.port ? `:${window.location.port}` : '';
const API_BASE_URL = `${API_PROTOCOL}//${API_HOST}${API_PORT}/api/v1`;

class SentinelAPI {
  constructor(baseURL = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  /**
   * Make HTTP request to the API
   */
  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.detail || `HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`API Error [${endpoint}]:`, error);
      throw error;
    }
  }

  // ============= DASHBOARD ENDPOINTS =============
  
  /**
   * Get dashboard summary
   */
  async getDashboardSummary() {
    return this.request('/dashboard/summary', {
      method: 'GET',
    });
  }

  /**
   * Get dashboard threats
   */
  async getDashboardThreats() {
    return this.request('/dashboard/threats', {
      method: 'GET',
    });
  }

  /**
   * Get dashboard statistics
   */
  async getDashboardStats() {
    return this.request('/dashboard/stats', {
      method: 'GET',
    });
  }

  /**
   * Get dashboard security posture
   */
  async getSecurityPosture() {
    return this.request('/dashboard/security-posture', {
      method: 'GET',
    });
  }

  /**
   * Get dashboard API status
   */
  async getApiStatus() {
    return this.request('/dashboard/api-status', {
      method: 'GET',
    });
  }

  /**
   * Get local quarantine inventory
   */
  async getQuarantineInventory() {
    return this.request('/dashboard/quarantine-inventory', {
      method: 'GET',
    });
  }

  // ============= SCAN ENDPOINTS =============
  
  /**
   * Scan a file
   */
  async scanFile(fileData) {
    const formData = new FormData();
    formData.append('file', fileData);

    return this.request('/scan/file', {
      method: 'POST',
      headers: {},
      body: formData,
    });
  }

  /**
   * Scan a URL
   */
  async scanUrl(url) {
    return this.request('/scan/url', {
      method: 'POST',
      body: JSON.stringify({ target: url }),
    });
  }

  /**
   * Get scan results
   */
  async getScanResults(scanId) {
    return this.request(`/scan/results/${scanId}`, {
      method: 'GET',
    });
  }

  // ============= THREATS ENDPOINTS =============
  
  /**
   * Get all threats
   */
  async getThreats() {
    return this.request('/threats', {
      method: 'GET',
    });
  }

  /**
   * Get threat details
   */
  async getThreatDetails(threatId) {
    return this.request(`/threats/${threatId}`, {
      method: 'GET',
    });
  }

  /**
   * Scan an IP address
   */
  async scanIP(ipAddress) {
    return this.request('/scan/ip', {
      method: 'POST',
      body: JSON.stringify({ target: ipAddress }),
    });
  }

  // ============= AUTH ENDPOINTS =============
  
  /**
   * Login user
   */
  async login(username, password) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  }

  /**
   * Get current user info
   */
  async getCurrentUser() {
    return this.request('/auth/me', {
      method: 'GET',
    });
  }

  // ============= HEALTH ENDPOINT =============
  
  /**
   * Check API health
   */
  async health() {
    return this.request('/health', {
      method: 'GET',
    });
  }
}

// Create global API instance
const api = new SentinelAPI();

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SentinelAPI, api };
}
