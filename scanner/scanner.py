import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Any

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: requests module not installed. Run: pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .port_scanner import PortScanner
from .http_analyzer import HTTPAnalyzer
from .tls_checker import TLSChecker
from .screenshot import ScreenshotCapture
from .vulnerability import VulnerabilityAnalyzer
from .reporter import ReportGenerator
from .utils import normalize_target, is_external_ip


class VulnerabilityScanner:
    """Main scanner class that orchestrates all scanning components."""
    
    def __init__(self, target: str, ports: List[int], timeout: float, workers: int, 
                 use_rich: bool = True, verbose: bool = False, allow_external: bool = False,
                 enable_screenshots: bool = False):
        self.target = normalize_target(target)
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        self.use_rich = use_rich and RICH_AVAILABLE
        self.verbose = verbose
        self.allow_external = allow_external
        self.enable_screenshots = enable_screenshots
        
        # Initialize components
        self.port_scanner = PortScanner(self.target, self.timeout, self.verbose)
        self.http_analyzer = HTTPAnalyzer(self.target, self.timeout, self.verbose)
        self.tls_checker = TLSChecker(self.target, self.timeout, self.verbose)
        self.screenshot_capture = ScreenshotCapture(self.target, self.verbose)
        self.vulnerability_analyzer = VulnerabilityAnalyzer()
        self.reporter = ReportGenerator(self.use_rich)
        
        self.console = Console() if self.use_rich else None
        
        self.results = {
            'target': self.target,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'ports': [],
            'http_headers': {},
            'tls_cert': {},
            'vulnerabilities': [],
            'screenshots': [],
            'risk_score': 0,
            'errors': []
        }
    
    def safety_check(self) -> bool:
        """Perform safety checks before scanning."""
        if is_external_ip(self.target) and not self.allow_external:
            warning_msg = (
                f"SAFETY WARNING: Target {self.target} appears to be an external/public IP.\n"
                "Scanning external systems without explicit permission may be illegal.\n"
                "Use --allow-external only if you have explicit permission to scan this target."
            )
            if self.use_rich:
                self.console.print(Panel(Text(warning_msg, style="bold red"), 
                                       title="⚠️  SECURITY WARNING", border_style="red"))
            else:
                print(f"⚠️  SECURITY WARNING: {warning_msg}")
            return False
        
        # Always show safety reminder
        safety_msg = "REMINDER: Only scan systems you own or have explicit permission to test."
        if self.use_rich:
            self.console.print(Panel(Text(safety_msg, style="bold yellow"), 
                                   title="🔒 Safety Notice", border_style="yellow"))
        else:
            print(f"🔒 Safety Notice: {safety_msg}")
            
        return True
    
    def run_scan(self) -> Dict[str, Any]:
        """Execute the complete vulnerability scan."""
        # Safety check
        if not self.safety_check():
            return self.results
        
        # Display scan info
        if self.use_rich:
            self.console.print(Panel(
                f"Target: [bold]{self.target}[/bold]\n"
                f"Ports: {', '.join(map(str, self.ports))}\n"
                f"Workers: {self.workers}\n"
                f"Timeout: {self.timeout}s\n"
                f"Screenshots: {'Enabled' if self.enable_screenshots else 'Disabled'}",
                title="🔍 Mini Vulnerability Scanner",
                border_style="blue"
            ))
        else:
            print(f"Mini Vulnerability Scanner - Target: {self.target}")
            print(f"Ports: {', '.join(map(str, self.ports))}")
            print(f"Workers: {self.workers}, Timeout: {self.timeout}s")
            print(f"Screenshots: {'Enabled' if self.enable_screenshots else 'Disabled'}")
        
        # Port scanning
        if self.use_rich:
            self.console.print(f"[bold blue]🔍 Scanning {len(self.ports)} ports on {self.target}...[/bold blue]")
        else:
            print(f"Scanning {len(self.ports)} ports on {self.target}...")
        
        port_results = self.port_scanner.scan_ports(self.ports, self.workers)
        self.results['ports'] = port_results
        
        # Display port scan results
        for result in port_results:
            if self.verbose or result['state'] == 'open':
                status_icon = "🟢" if result['state'] == 'open' else "🔴"
                if self.use_rich:
                    style = "green" if result['state'] == 'open' else "dim"
                    banner_preview = result['banner'][:50] + "..." if len(result['banner']) > 50 else result['banner']
                    self.console.print(
                        f"  {status_icon} Port {result['port']}: {result['state']} "
                        f"([bold]{result['service']}[/bold]) {banner_preview}"
                    )
                else:
                    print(f"  {status_icon} Port {result['port']}: {result['state']} "
                          f"({result['service']}) {result['banner'][:50] if result['banner'] else ''}")
        
        # HTTP/HTTPS checks
        open_ports = [p for p in self.results['ports'] if p['state'] == 'open']
        http_ports = [p for p in open_ports if p['port'] in [80, 443, 8080, 8443] or p['service'] in ['http', 'https', 'apache', 'nginx', 'iis']]
        
        for port_info in http_ports:
            port = port_info['port']
            scheme = 'https' if port in [443, 8443] or port_info['service'] == 'https' else 'http'
            
            if self.use_rich:
                self.console.print(f"[bold yellow]🔒 Checking {scheme.upper()} headers on port {port}...[/bold yellow]")
            else:
                print(f"Checking {scheme.upper()} headers on port {port}...")
            
            headers_result = self.http_analyzer.check_http_headers(port, scheme)
            if headers_result['error']:
                self.results['errors'].append(headers_result['error'])
            else:
                self.results['http_headers'][f"{scheme}_{port}"] = headers_result
            
            # Capture screenshot if enabled
            if self.enable_screenshots and scheme in ['http', 'https']:
                screenshot_result = self.screenshot_capture.capture_screenshot(
                    headers_result['url'], port
                )
                if screenshot_result:
                    self.results['screenshots'].append(screenshot_result)
        
        # TLS certificate check
        https_ports = [p for p in open_ports if p['port'] == 443 or p['service'] == 'https']
        if https_ports:
            if self.use_rich:
                self.console.print("[bold yellow]🔐 Checking TLS certificate...[/bold yellow]")
            else:
                print("Checking TLS certificate...")
            tls_result = self.tls_checker.check_tls_certificate()
            if tls_result['error']:
                self.results['errors'].append(tls_result['error'])
            else:
                self.results['tls_cert'] = tls_result
        
        # Vulnerability assessment
        self.results['vulnerabilities'] = self.vulnerability_analyzer.check_common_vulnerabilities(self.results)
        self.results['risk_score'] = self.vulnerability_analyzer.calculate_risk_score(self.results)
        
        return self.results
    
    def display_results(self) -> None:
        """Display results using the reporter."""
        self.reporter.display_results(self.results)