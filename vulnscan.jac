include "security.jac";

# Vuln target extends base with web-specific data
node VulnTarget: SecTarget {
    has http_status: int = 0;
    has server_banner: str = "";
    has ssl_enabled: bool = false;
    has vulns_found: [] = [];
}

walker VulnScanner: SecScanner {
    # Check common web vulns on open HTTP/HTTPS ports
    can check_web_vulns(host: str) with VulnTarget entry {
        here.host = host;
        self.log_result(f"Checking web vulnerabilities on {host}");
        
        # Test HTTP (80) and HTTPS (443)
        ports_to_check = [80, 443];
        
        for port in ports_to_check {
            if self.portscan.test_port(port, host) {
                self.check_http_vulns(port, host);
            }
        }
    }
    
    can check_http_vulns(port: int, host: str) with VulnTarget entry {
        # Simplified HTTP header check via socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        sock.settimeout(self.timeout);
        
        if sock.connect_ex((host, port)) == 0 {
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n");
            response = sock.recv(1024);
            sock.close();
            
            here.server_banner = str(response);
            
            # Check for vulnerable servers
            if b"Apache/2.4.49" in response {
                here.vulns_found.append("Apache Path Traversal CVE-2021-41773");
                self.log_result(f"  ⚠️ VULN: Apache 2.4.49 detected on port {port}");
            }
            if b"nginx/1.20.1" in response {
                here.vulns_found.append("nginx 1.20.1 known issues");
                self.log_result(f"  ⚠️ VULN: nginx 1.20.1 on port {port}");
            }
        }
    }
}
