# SENTINEL-AI System Architecture & Deployment

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     SENTINEL-AI SERVER                          │
│                   (Your Central Server)                         │
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │  Database   │  │ Threat Intel │  │  Report Generator   │  │
│  │  (SQLite)   │  │  APIs        │  │  (PDF/JSON)         │  │
│  └─────────────┘  └──────────────┘  └─────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │           Network Defense & Monitoring Engine            │ │
│  │  • Client Registration    • Attack Detection             │ │
│  │  • Network-Wide Blocking  • Alert System                 │ │
│  └──────────────────────────────────────────────────────────┘ │
│                                                                 │
│         API: http://YOUR_IP:8000                               │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ Internet / Network
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   CLIENT 1   │    │   CLIENT 2   │    │   CLIENT 3   │
│  (Linux)     │    │  (Windows)   │    │  (macOS)     │
│              │    │              │    │              │
│ ┌──────────┐ │    │ ┌──────────┐ │    │ ┌──────────┐ │
│ │  Scan    │ │    │ │  Scan    │ │    │ │  Scan    │ │
│ │  Engine  │ │    │ │  Engine  │ │    │ │  Engine  │ │
│ └──────────┘ │    │ └──────────┘ │    │ └──────────┘ │
│              │    │              │    │              │
│ ┌──────────┐ │    │ ┌──────────┐ │    │ ┌──────────┐ │
│ │ Defense  │ │    │ │ Defense  │ │    │ │ Defense  │ │
│ │ System   │ │    │ │ System   │ │    │ │ System   │ │
│ └──────────┘ │    │ └──────────┘ │    │ └──────────┘ │
│              │    │              │    │              │
│ Monitors:    │    │ Monitors:    │    │ Monitors:    │
│ • Files      │    │ • Files      │    │ • Files      │
│ • Network    │    │ • Network    │    │ • Network    │
│ • Processes  │    │ • Processes  │    │ • Processes  │
└──────────────┘    └──────────────┘    └──────────────┘
```

## Deployment Flow

```
Step 1: Server Setup
┌─────────────────────────────────────────────────────┐
│ YOU (Administrator)                                 │
│                                                     │
│ $ cd server                                         │
│ $ ./setup_server.sh                                 │
│                                                     │
│ ✓ Dependencies installed                           │
│ ✓ Database created                                 │
│ ✓ Admin credentials generated                      │
│ ✓ Server ready at http://YOUR_IP:8000             │
└─────────────────────────────────────────────────────┘
                      │
                      ▼
Step 2: Client Deployment (For Each System)
┌─────────────────────────────────────────────────────┐
│ YOUR CLIENT (End User)                              │
│                                                     │
│ $ ./setup_client.sh http://SERVER:8000 API_KEY     │
│                                                     │
│ ✓ Python environment configured                    │
│ ✓ Client registered with server                    │
│ ✓ Protection started                               │
│ ✓ Monitoring active                                │
└─────────────────────────────────────────────────────┘
                      │
                      ▼
Step 3: Automatic Protection
┌─────────────────────────────────────────────────────┐
│ CONTINUOUS MONITORING                               │
│                                                     │
│ Client scans:                                       │
│ • File downloads     → Server analyzes             │
│ • Network traffic    → Threat detection            │
│ • URL access         → API queries                 │
│ • Process activity   → AI analysis                 │
│                                                     │
│ If threat detected:                                │
│ 1. Alert server                                    │
│ 2. Server blocks threat                            │
│ 3. Block propagates to all clients                 │
│ 4. Network alert generated                         │
└─────────────────────────────────────────────────────┘
```

## Data Flow

```
CLIENT DETECTS THREAT
        │
        ▼
┌───────────────────┐
│  1. Client Scans  │
│     Suspicious    │
│     Activity      │
└─────────┬─────────┘
          │
          ▼
┌───────────────────┐
│  2. Send to       │
│     Server for    │
│     Analysis      │
└─────────┬─────────┘
          │
          ▼
┌───────────────────────────────────────┐
│  3. SERVER ANALYSIS                   │
│     ┌──────────────────────────┐     │
│     │ • VirusTotal             │     │
│     │ • AbuseIPDB              │     │
│     │ • Shodan                 │     │
│     │ • URLScan                │     │
│     │ • AI Analysis (Gemini)   │     │
│     └──────────────────────────┘     │
└─────────┬─────────────────────────────┘
          │
          ▼
┌───────────────────┐
│  4. VERDICT:      │
│     Malicious     │
└─────────┬─────────┘
          │
          ├──────────────────────┬─────────────────┐
          ▼                      ▼                 ▼
┌─────────────────┐  ┌──────────────────┐  ┌──────────────┐
│ 5a. Block on    │  │ 5b. Record in    │  │ 5c. Generate │
│     Client      │  │     Database     │  │     Alert    │
│     (iptables)  │  │                  │  │              │
└─────────────────┘  └──────────────────┘  └──────────────┘
          │
          ▼
┌─────────────────────────────────────────┐
│  6. NETWORK-WIDE PROPAGATION            │
│                                         │
│  Same threat blocked on ALL clients:    │
│  • Client 1: ✓ Blocked                 │
│  • Client 2: ✓ Blocked                 │
│  • Client 3: ✓ Blocked                 │
└─────────────────────────────────────────┘
```

## Reporting Flow

```
GENERATE REPORT REQUEST
        │
        ▼
┌─────────────────────────────────────────┐
│ SERVER QUERIES DATABASE                 │
│                                         │
│ SELECT * FROM scan_history              │
│ WHERE timestamp >= NOW() - 24 hours     │
│                                         │
│ JOIN client_installations               │
│ JOIN attack_events                      │
│ JOIN defense_actions                    │
└─────────┬───────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────┐
│ AGGREGATE DATA BY:                      │
│ • Time interval (24h, 7d, 30d)         │
│ • Scan type (file, URL, IP, domain)    │
│ • Client system                         │
│ • Threat level                          │
└─────────┬───────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────┐
│ GENERATE PDF/JSON                       │
│                                         │
│ Includes:                               │
│ • Statistics summary                    │
│ • Threat timeline                       │
│ • Top threats                           │
│ • Attack events                         │
│ • Defense actions                       │
│ • AI recommendations                    │
└─────────┬───────────────────────────────┘
          │
          ▼
┌─────────────────┐
│ DELIVER REPORT  │
│ (PDF Download)  │
└─────────────────┘
```

## Network Architecture

```
                INTERNET
                    │
                    ▼
            ┌──────────────┐
            │   Firewall   │
            │  Port 8000   │
            └──────┬───────┘
                   │
                   ▼
         ┌────────────────────┐
         │   SENTINEL-AI      │
         │      SERVER        │
         │  192.168.1.10:8000 │
         └────────┬───────────┘
                  │
         ┌────────┴────────┐
         │  Internal LAN   │
         │  192.168.1.0/24 │
         └────────┬────────┘
                  │
      ┌───────────┼───────────┐
      │           │           │
      ▼           ▼           ▼
┌──────────┐ ┌──────────┐ ┌──────────┐
│ CLIENT 1 │ │ CLIENT 2 │ │ CLIENT 3 │
│ .100     │ │ .101     │ │ .102     │
└──────────┘ └──────────┘ └──────────┘

All clients:
• Register with server
• Send heartbeat every 60s
• Report threats immediately
• Receive block lists
• Execute defense actions
```

## Component Breakdown

### Server Components

```
server/
├── app/
│   ├── models.py              # Database models
│   ├── database.py            # DB connection
│   ├── api/
│   │   └── v1/
│   │       └── endpoints/
│   │           ├── scan.py               # Scan endpoints
│   │           ├── advanced_reports.py   # Report generation
│   │           └── network_defense.py    # Defense system
│   └── core/
│       ├── threat_analyzer.py    # Threat analysis
│       └── report_generator.py   # PDF generation
├── setup_server.sh           # Automated setup
├── migrate_database.py       # DB initialization
└── run_server.py            # Server startup
```

### Client Components

```
client/
├── sentinel_client_enhanced.py   # Main client
├── setup_client.sh               # Automated setup
├── config.ini                    # Configuration
└── scanner/
    ├── file_scanner.py          # File monitoring
    ├── network_scanner.py       # Network monitoring
    └── process_scanner.py       # Process monitoring
```

## Security Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Layer 1: Authentication                               │
│  ├── API Key per client                               │
│  ├── JWT tokens                                       │
│  └── Client ID verification                           │
│                                                         │
│  Layer 2: Communication                                │
│  ├── HTTPS (recommended)                              │
│  ├── Rate limiting                                    │
│  └── Request validation                               │
│                                                         │
│  Layer 3: Defense                                      │
│  ├── Firewall rules (iptables/Windows FW)            │
│  ├── Hosts file blocking                              │
│  ├── Real-time threat blocking                        │
│  └── Network-wide coordination                        │
│                                                         │
│  Layer 4: Monitoring                                   │
│  ├── Continuous scanning                              │
│  ├── Heartbeat monitoring                             │
│  ├── Activity logging                                 │
│  └── Alert system                                     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Deployment Scenarios

### Scenario 1: Small Office (5-10 Computers)

```
[Server]       [Switch/Router]       [Clients 1-10]
  (1)      →         →                  →
  
Setup Time: 30 minutes
Method: Manual setup on each client
Monitoring: Daily reports via email
```

### Scenario 2: Medium Business (50-100 Computers)

```
[Server]    [Network Infrastructure]    [Clients 1-100]
  (1)     →     [Distributed]        →     [Automated]

Setup Time: 2 hours
Method: Ansible/Group Policy deployment
Monitoring: Real-time dashboard + automated reports
```

### Scenario 3: Enterprise (500+ Computers)

```
[HA Servers]  [Load Balancer]  [Network Zones]  [Clients 1-1000+]
   (2+)    →        →                →              [Automated]

Setup Time: 1 day (planning) + automated rollout
Method: Enterprise deployment tools (SCCM/Ansible/Puppet)
Monitoring: SOC integration + automated alerting
```

## Scaling Considerations

```
Small Deployment (< 50 clients)
├── Single server
├── SQLite database
└── Direct client connections

Medium Deployment (50-500 clients)
├── Single/dual servers
├── PostgreSQL database
├── Load balancer (optional)
└── Client zones

Large Deployment (500+ clients)
├── Multiple servers (HA)
├── PostgreSQL cluster
├── Load balancer required
├── CDN for static files
└── Distributed architecture
```

---

**SENTINEL-AI** - Enterprise-Ready Architecture 🏗️
