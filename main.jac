include "security.jac";
include "portscan.jac";
include "vulnscan.jac";
include "netscan.jac";
include "report.jac";

with entry {
    print("🔒 Jac Security Library - In development by Johnson.");
    print("=========================================");
    print("Enter target details:");
    
    # Interactive user input for target host
    target_host = input("Target host/IP (default: scanme.nmap.org): ") or "scanme.nmap.org";
    network_range = input("Network range for discovery (default: 192.168.1.): ") or "192.168.1.";
    
    print(f"\n🎯 Using target: {target_host}");
    print(f"🌐 Network range: {network_range}");
    
    # 1️⃣ Port Scan
    print("\n 1️⃣ PORT SCANNING...");
    port_target = root ++> PortTarget(host=target_host);
    port_scanner = PortScanner();
    port_target spawn port_scanner.quick_scan(target_host);
    
    # 2️⃣ Vulnerability Scan  
    print("\n 2️⃣ VULNERABILITY SCANNING...");
    vuln_target = root ++> VulnTarget(host=target_host);
    vuln_scanner = VulnScanner();
    vuln_target spawn vuln_scanner.check_web_vulns(target_host);
    
    # 3️⃣ Network Discovery
    print("\n 3️⃣ NETWORK DISCOVERY...");
    net_target = root ++> NetTarget(network=network_range);
    net_scanner = NetScanner();
    net_target spawn net_scanner.discover_hosts(network_range);
    
    # 4️⃣ GENERATE REPORTS
    print("\n 4️⃣ GENERATING REPORTS...");
    report_format = input("Report format (json/csv/text): ") or "json";
    
    report = root ++> Report(export_format=report_format);
    report_generator = ReportGenerator();
    report spawn report_generator.generate_report();
    
    print("\n✅ SCAN COMPLETE!");
    print(f"📄 Reports saved as security_report.{report_format}");
    print("📈 Graph visualization: jac vis");
}
