# Jac Security Library

A modular **Jac-based security toolkit** for port scanning, vulnerability detection, network discovery, and professional reporting. Built with Jac's Object-Spatial Programming (OSP) paradigm for scalable, graph-persisted security audits.

## 🚀 Features
- **Port Scanning** - Common ports + full range scans
- **Vulnerability Detection** - HTTP headers, CVE patterns
- **Network Discovery** - Ping sweeps, live host detection
- **Professional Reports** - JSON/CSV/TXT export
- **Graph Persistence** - Results saved in Jac graph DB
- **Interactive + CLI** - User-friendly input options

## 📁 Structure
security_lib/
├── security.jac      # Base classes & logging
├── portscan.jac      # TCP port scanner
├── vulnscan.jac      # Web vulnerability checks
├── netscan.jac       # Network/host discovery
├── report.jac        # JSON/CSV/TXT reporting
├── main.jac          # Full suite (interactive)
└── main_cli.jac      # CLI version


## 🛠️ Installation & Setup

1. **Install Jac**

pip install jaclang
jac --version  


2. **Create Library**
mkdir security_lib && cd security_lib
# Copy all .jac files from this repo or clone this repo



3. **Build & Test**
```bash
jac build .          
jac run main.jac      


## 🎯 Usage Examples

### Interactive Mode (Recommended)
jac run main.jac

Target host/IP (default: scanme.nmap.org): 89.117.37.114
Network range (default: 192.168.1.): 192.168.1.
Report format (json/csv/text): json

**Generates**: `security_report.json`

### Individual Modules
jac run portscan.jac    # Quick common ports
jac run vulnscan.jac    # Web vuln checks
jac run netscan.jac     # Network discovery

## 📊 Sample Output

🔒 Jac Security Library
=========================================
🎯 Target: 192.168.1.
🌐 Network: 192.168.1.

1️⃣ PORT SCANNING...
  ✓ Port 80 OPEN
  ✓ Port 443 OPEN

2️⃣ VULNERABILITY SCANNING...
  ⚠️ VULN: Apache 2.4.49 detected on port 80

3️⃣ NETWORK DISCOVERY...
  🟢 Live host: 192.168.1.1

📊 SECURITY SCAN SUMMARY
=======================
Total Hosts: 3 | Open Ports: 2 | Vulns: 1 | Risk: HIGH
```


## 🛡️ Safe Testing Targets
- **Public**: `scanme.nmap.org` (Nmap test server)
- **Local**: `127.0.0.1` or `localhost`


## 🙌 Credits
Built by Johnson. Powered by Jac **Object-Spatial Programming**.



Scan securely. Report professionally. Scale infinitely. 🚀


jac run main.jac 
