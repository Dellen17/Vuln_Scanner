import socket
from urllib.parse import urlparse
from typing import List


def normalize_target(target: str) -> str:
    """Extract hostname from URL if provided, otherwise return as-is."""
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        # Handle URLs with ports like http://localhost:8080
        if parsed.port:
            return parsed.hostname
        return parsed.hostname or target
    return target


def is_external_ip(ip: str) -> bool:
    """Check if IP is external (not localhost or private)."""
    if ip in ['localhost', '127.0.0.1', '::1']:
        return False
    
    try:
        # Handle hostnames by resolving to IP
        ip_addr = socket.gethostbyname(ip)
    except socket.gaierror:
        # If we can't resolve, assume it's external to be safe
        return True
    
    # Private IP ranges
    private_ranges = [
        ('10.', 8),
        ('172.16.', 12),
        ('172.17.', 12),
        ('172.18.', 12),
        ('172.19.', 12),
        ('172.20.', 12),
        ('172.21.', 12),
        ('172.22.', 12),
        ('172.23.', 12),
        ('172.24.', 12),
        ('172.25.', 12),
        ('172.26.', 12),
        ('172.27.', 12),
        ('172.28.', 12),
        ('172.29.', 12),
        ('172.30.', 12),
        ('172.31.', 12),
        ('192.168.', 16),
        ('169.254.', 16)  # Link-local
    ]
    
    for prefix, _ in private_ranges:
        if ip_addr.startswith(prefix):
            return False
    
    return True