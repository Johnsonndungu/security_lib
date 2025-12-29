node PortTarget: SecTarget {
    has open_ports: [] = [];
    has common_ports: [] = [21,22,23,25,53,80,110,443,993,995];
}

walker PortScanner: SecScanner {
    can quick_scan(host: str) with PortTarget entry {
        here.host = host;
        self.log_result(f"Quick scanning {host} common ports");
        
        for port in here.common_ports {
            if self.test_port(port, host) {
                here.open_ports.append(port);
                self.log_result(f"Port {port} OPEN");
            }
        }
    }
    
    can test_port(port: int, host: str) with entry {
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        sock.settimeout(self.timeout);
        result = sock.connect_ex((host, port));
        sock.close();
        return result == 0;
    }
}
