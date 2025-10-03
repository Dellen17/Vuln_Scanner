"""
Main entry point when running as module: python -m scanner
"""

import sys

def main():
    # Check if 'scan' command is provided
    if len(sys.argv) > 1 and sys.argv[1] == 'scan':
        # Remove 'scan' and pass remaining args to CLI
        sys.argv.pop(1)
        from .cli import main as cli_main
        cli_main()
    else:
        print("Usage: python -m scanner scan [options]")
        print("Try: python -m scanner scan --target 192.168.1.50 --ports 80,443 --screenshot")
        sys.exit(1)

if __name__ == "__main__":
    main()