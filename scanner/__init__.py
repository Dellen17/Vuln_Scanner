"""
Mini Vulnerability Scanner Package
Educational purpose only - only scan systems you own or have explicit permission to test.
"""

__version__ = "2.0.0"
__author__ = "Vulnerability Scanner Team"

from .scanner import VulnerabilityScanner
from .cli import main

__all__ = ['VulnerabilityScanner', 'main']