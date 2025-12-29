include "portscan.jac";
include "vulnscan.jac";
include "netscan.jac";
include "report.jac";

# Base security node (all tools inherit)
node SecTarget {
    has host: str;
    has scan_results: str = "";
    has risk_score: int = 0;
}

# Base scanner walker template
walker SecScanner {
    has timeout: int = 3;
    
    can log_result(msg: str) {
        print(f"[SEC] {msg}");
    }
}
