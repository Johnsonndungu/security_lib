include "security.jac";
include "portscan.jac";
include "vulnscan.jac";
include "netscan.jac";

# Report node - aggregates all scan data
node Report {
    has targets: [] = [];  # List of SecTarget nodes
    has summary: str = "";
    has export_format: str = "json";  # json, csv, text
    has timestamp: str = "";
}

walker ReportGenerator: SecScanner {
    # Generate comprehensive report from all targets
    can generate_report() with Report entry {
        self.log_result("🔄 Generating security report...");
        
        # Collect all SecTarget nodes from graph
        all_targets = root ^^> SecTarget;  # Traverse edges to all SecTargets
        here.targets = all_targets;
        
        self.build_summary();
        self.export_report();
    }
    
    can build_summary() with Report entry {
        total_hosts = len(here.targets);
        open_ports_total = 0;
        vulns_total = 0;
        live_hosts = 0;
        
        for target in here.targets {
            if target isa PortTarget {
                open_ports_total += len(target.open_ports);
            }
            if target isa VulnTarget {
                vulns_total += len(target.vulns_found);
            }
            if target isa NetTarget {
                live_hosts += len(target.live_hosts);
            }
        }
        
        here.summary = f"""
        📊 SECURITY SCAN SUMMARY
        ========================
        Total Hosts Scanned: {total_hosts}
        Live Hosts Found: {live_hosts}
        Open Ports: {open_ports_total}
        Vulnerabilities: {vulns_total}
        Risk Level: {'HIGH' if vulns_total > 0 else 'LOW'}
        Timestamp: {here.timestamp}
        """;
        
        print(here.summary);
    }
    
    # Export to JSON/CSV/Text
    can export_report() with Report entry {
        if here.export_format == "json" {
            self.export_json();
        } else if here.export_format == "csv" {
            self.export_csv();
        } else {
            self.export_text();
        }
    }
    
    can export_json() with Report entry {
        report_data = {
            "summary": here.summary,
            "targets": [],
            "timestamp": here.timestamp
        };
        
        for target in here.targets {
            target_data = {
                "host": target.host,
                "scan_results": target.scan_results,
                "risk_score": target.risk_score
            };
            if target isa PortTarget {
                target_data["open_ports"] = target.open_ports;
            }
            if target isa VulnTarget {
                target_data["vulns"] = target.vulns_found;
            }
            report_data["targets"].append(target_data);
        }
        
        # Save to file (Jac file ops)
        import json;
        file_content = json.dumps(report_data);
        with open("security_report.json", "w") as f {
            f.write(file_content);
        }
        self.log_result("📄 Report saved: security_report.json");
    }
    
    can export_csv() with Report entry {
        csv_content = "Host,Risk Score,Open Ports,Vulnerabilities\n";
        
        for target in here.targets {
            ports = "";
            vulns = "";
            
            if target isa PortTarget {
                ports = ",".join(map(str, target.open_ports));
            }
            if target isa VulnTarget {
                vulns = ",".join(target.vulns_found);
            }
            
            csv_content += f"{target.host},{target.risk_score},{ports},{vulns}\n";
        }
        
        with open("security_report.csv", "w") as f {
            f.write(csv_content);
        }
        self.log_result("📄 Report saved: security_report.csv");
    }
    
    can export_text() with Report entry {
        report_text = here.summary + "\n\nDETAILED FINDINGS:\n";
        
        for target in here.targets {
            report_text += f"\n🖥️  {target.host}\n";
            report_text += f"   Risk: {target.risk_score}/10\n";
            report_text += f"   Results: {target.scan_results}\n";
        }
        
        with open("security_report.txt", "w") as f {
            f.write(report_text);
        }
        self.log_result("📄 Report saved: security_report.txt");
    }
}
