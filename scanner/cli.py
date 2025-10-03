import argparse
import json
import sys
from .scanner import VulnerabilityScanner


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Mini Vulnerability Scanner - Educational tool for security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SAFETY WARNING: Only scan systems you own or have explicit permission to test.
Unauthorized scanning may be illegal in your jurisdiction.

Screenshot feature requires: pip install playwright && playwright install
        """
    )
    
    parser.add_argument('--target', '-t', required=True, 
                       help='Target hostname or IP (e.g., 192.168.1.100 or http://localhost:8080)')
    parser.add_argument('--ports', '-p', default='21,22,80,443,3306',
                       help='Comma-separated list of ports (default: 21,22,80,443,3306)')
    parser.add_argument('--timeout', type=float, default=1.5,
                       help='Connection timeout in seconds (default: 1.5)')
    parser.add_argument('--workers', type=int, default=8,
                       help='Number of concurrent threads (default: 8)')
    parser.add_argument('--save', 
                       help='Filename to save JSON report (optional)')
    parser.add_argument('--no-rich', action='store_true',
                       help='Disable rich output formatting')
    parser.add_argument('--screenshot', action='store_true',
                       help='Enable screenshot capture (requires Playwright)')
    parser.add_argument('--allow-external', action='store_true',
                       help='Explicitly allow scanning of external/public IPs')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = [int(port.strip()) for port in args.ports.split(',')]
    except ValueError:
        print("Error: Ports must be comma-separated integers")
        sys.exit(1)
    
    # Initialize scanner
    scanner = VulnerabilityScanner(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        workers=args.workers,
        use_rich=not args.no_rich,
        verbose=args.verbose,
        allow_external=args.allow_external,
        enable_screenshots=args.screenshot
    )
    
    # Run scan
    try:
        results = scanner.run_scan()
        scanner.display_results()
        
        # Save report if requested
        if args.save:
            with open(args.save, 'w') as f:
                json.dump(results, f, indent=2)
            if scanner.use_rich:
                scanner.console.print(f"\n[green]📄 Report saved to: {args.save}[/green]")
            else:
                print(f"\nReport saved to: {args.save}")
                
    except KeyboardInterrupt:
        if scanner.use_rich:
            scanner.console.print("\n[yellow]Scan interrupted by user[/yellow]")
        else:
            print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        if args.verbose:
            raise
        print(f"Error during scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()