include "security.jac";

node NetTarget: SecTarget {
    has live_hosts: [] = [];
    has network_range: str = "";
}

walker NetScanner: SecScanner {
    # Ping sweep (ICMP simulation via TCP/UDP)
    can discover_hosts(network: str) with NetTarget entry {
        here.network_range = network;
        self.log_result(f"Network discovery on {network} (ports 22,80,443)");
        
        # Simple ping via TCP connect to common ports
        base_ip = network.rsplit(".", 1)[0] + ".";
        for i in range(1, 255) {
            test_ip = base_ip + str(i);
            if self.ping_host(test_ip) {
                here.live_hosts.append(test_ip);
                self.log_result(f"  🟢 Live host: {test_ip}");
            }
        }
    }
    
    can ping_host(ip: str) with entry {
        # TCP ping on SSH/HTTP/HTTPS (firewall bypass)
        ports = [22, 80, 443];
        for port in ports {
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
            sock.settimeout(1);
            if sock.connect_ex((ip, port)) == 0 {
                sock.close();
                return true;
            }
            sock.close();
        }
        return false;
    }
}
