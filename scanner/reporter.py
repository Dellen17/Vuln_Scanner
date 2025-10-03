from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


class ReportGenerator:
    """Handles result display and reporting in both rich and plain text formats."""
    
    def __init__(self, use_rich: bool = True):
        self.use_rich = use_rich
        self.console = Console() if use_rich else None
    
    def display_results(self, results: Dict[str, Any]) -> None:
        """Display results in appropriate format."""
        if self.use_rich:
            self._display_results_rich(results)
        else:
            self._display_results_plain(results)
    
    def _display_results_rich(self, results: Dict[str, Any]) -> None:
        """Display results using rich formatting."""
        # Open ports table
        open_ports = [p for p in results['ports'] if p['state'] == 'open']
        if open_ports:
            table = Table(title="📡 Open Ports", show_header=True, header_style="bold magenta")
            table.add_column("Port", style="cyan")
            table.add_column("Service", style="green")
            table.add_column("State", style="bold green")
            table.add_column("Banner", style="white")
            
            for port in open_ports:
                banner_preview = port['banner'][:100] + "..." if len(port['banner']) > 100 else port['banner']
                table.add_row(
                    str(port['port']),
                    port['service'],
                    port['state'],
                    banner_preview
                )
            self.console.print(table)
        else:
            self.console.print("[yellow]No open ports found.[/yellow]")
        
        # HTTP headers
        if results['http_headers']:
            for service, headers_info in results['http_headers'].items():
                table = Table(title=f"🌐 HTTP Headers - {headers_info['url']}", show_header=True, header_style="bold blue")
                table.add_column("Header", style="cyan")
                table.add_column("Status", style="white")
                
                # Headers found
                for header, value in headers_info['headers_found'].items():
                    value_preview = str(value)[:100] + "..." if len(str(value)) > 100 else str(value)
                    table.add_row(header, f"✅ Present: {value_preview}")
                
                # Headers missing
                for header in headers_info['headers_missing']:
                    table.add_row(header, "❌ Missing")
                
                self.console.print(table)
        else:
            self.console.print("[yellow]No HTTP services found or accessible.[/yellow]")
        
        # TLS certificate
        if results['tls_cert']:
            cert = results['tls_cert']
            expiry_status = "✅ Valid" 
            if cert['is_expired']:
                expiry_status = "❌ EXPIRED"
            elif cert['is_near_expiry']:
                expiry_status = "⚠️  Expires soon"
            
            cert_table = Table(title="🔐 TLS Certificate", show_header=True, header_style="bold green")
            cert_table.add_column("Field", style="cyan")
            cert_table.add_column("Value", style="white")
            
            issuer_name = cert.get('issuer', {}).get('organizationName', cert.get('issuer', {}).get('commonName', 'Unknown'))
            subject_name = cert.get('subject', {}).get('commonName', cert.get('subject', {}).get('organizationName', 'Unknown'))
            
            cert_table.add_row("Issuer", str(issuer_name))
            cert_table.add_row("Subject", str(subject_name))
            cert_table.add_row("Expiry", cert['expiry'])
            cert_table.add_row("Days until expiry", str(cert['days_until_expiry']))
            cert_table.add_row("Status", expiry_status)
            
            self.console.print(cert_table)
        else:
            self.console.print("[yellow]No TLS certificate found or HTTPS not available.[/yellow]")
        
        # Vulnerabilities
        if results['vulnerabilities']:
            vuln_table = Table(title="⚠️  Identified Vulnerabilities", show_header=True, header_style="bold red")
            vuln_table.add_column("Vulnerability", style="white")
            
            for vuln in results['vulnerabilities']:
                vuln_table.add_row(vuln)
            
            self.console.print(vuln_table)
        else:
            self.console.print("[green]✅ No specific vulnerabilities identified.[/green]")
        
        # Screenshots
        if results['screenshots']:
            screenshot_table = Table(title="📸 Screenshots Captured", show_header=True, header_style="bold cyan")
            screenshot_table.add_column("URL", style="white")
            screenshot_table.add_column("File", style="cyan")
            
            for screenshot in results['screenshots']:
                screenshot_table.add_row(screenshot['url'], screenshot['filepath'])
            
            self.console.print(screenshot_table)
        
        # Risk assessment
        risk_score = results['risk_score']
        risk_level = "Low" if risk_score < 25 else "Medium" if risk_score < 50 else "High"
        risk_color = "green" if risk_score < 25 else "yellow" if risk_score < 50 else "red"
        
        risk_table = Table(title="🔍 Risk Assessment", show_header=True, header_style="bold")
        risk_table.add_column("Metric", style="cyan")
        risk_table.add_column("Value", style=risk_color)
        
        risk_table.add_row("Risk Score", f"{risk_score}/100 ({risk_level})")
        
        self.console.print(risk_table)
        
        # Errors
        if results['errors']:
            self.console.print(Panel(
                "\n".join(results['errors']),
                title="⚠️  Errors During Scan",
                border_style="red"
            ))
    
    def _display_results_plain(self, results: Dict[str, Any]) -> None:
        """Display results in plain text format."""
        print("\n" + "="*50)
        print("SCAN RESULTS")
        print("="*50)
        
        # Open ports
        open_ports = [p for p in results['ports'] if p['state'] == 'open']
        if open_ports:
            print("\n📡 OPEN PORTS:")
            for port in open_ports:
                print(f"  Port {port['port']} ({port['service']}): {port['state']}")
                if port['banner']:
                    print(f"    Banner: {port['banner'][:100]}")
        else:
            print("\nNo open ports found.")
        
        # HTTP headers
        if results['http_headers']:
            print("\n🌐 HTTP HEADERS:")
            for service, headers_info in results['http_headers'].items():
                print(f"  {headers_info['url']} (Status: {headers_info['status_code']})")
                for header, value in headers_info['headers_found'].items():
                    print(f"    ✅ {header}: {value[:100]}")
                for header in headers_info['headers_missing']:
                    print(f"    ❌ {header}: Missing")
        else:
            print("\nNo HTTP services found or accessible.")
        
        # TLS certificate
        if results['tls_cert']:
            cert = results['tls_cert']
            print("\n🔐 TLS CERTIFICATE:")
            issuer_name = cert.get('issuer', {}).get('organizationName', cert.get('issuer', {}).get('commonName', 'Unknown'))
            subject_name = cert.get('subject', {}).get('commonName', cert.get('subject', {}).get('organizationName', 'Unknown'))
            print(f"  Issuer: {issuer_name}")
            print(f"  Subject: {subject_name}")
            print(f"  Expiry: {cert['expiry']}")
            print(f"  Days until expiry: {cert['days_until_expiry']}")
            status = "EXPIRED" if cert['is_expired'] else "Expires soon" if cert['is_near_expiry'] else "Valid"
            print(f"  Status: {status}")
        else:
            print("\nNo TLS certificate found or HTTPS not available.")
        
        # Vulnerabilities
        if results['vulnerabilities']:
            print("\n⚠️  VULNERABILITIES:")
            for vuln in results['vulnerabilities']:
                print(f"  • {vuln}")
        else:
            print("\n✅ No specific vulnerabilities identified.")
        
        # Screenshots
        if results['screenshots']:
            print("\n📸 SCREENSHOTS:")
            for screenshot in results['screenshots']:
                print(f"  {screenshot['url']} -> {screenshot['filepath']}")
        
        # Risk assessment
        risk_score = results['risk_score']
        risk_level = "Low" if risk_score < 25 else "Medium" if risk_score < 50 else "High"
        print(f"\n🔍 RISK ASSESSMENT:")
        print(f"  Risk Score: {risk_score}/100 ({risk_level})")
        
        # Errors
        if results['errors']:
            print("\n⚠️  ERRORS:")
            for error in results['errors']:
                print(f"  {error}")