import socket
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


class PortScanner:
    """Handles port scanning and service detection."""
    
    def __init__(self, target: str, timeout: float, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
    
    def scan_port(self, port: int) -> Dict[str, Any]:
        """Scan a single port and attempt banner grabbing."""
        result = {
            'port': port,
            'state': 'closed',
            'banner': '',
            'service': 'unknown',
            'error': None
        }
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                connection_result = sock.connect_ex((self.target, port))
                
                if connection_result == 0:
                    result['state'] = 'open'
                    
                    # Attempt banner grabbing for specific services
                    try:
                        sock.settimeout(0.5)  # Short timeout for banner
                        if port in [80, 443, 8080, 8443]:
                            # Send HTTP request for web services
                            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            result['banner'] = banner
                    except (socket.timeout, socket.error, BlockingIOError):
                        pass
                    
                    # Service detection
                    result['service'] = self.detect_service(port, result['banner'])
                    
                else:
                    result['state'] = 'closed'
                    
        except Exception as e:
            result['state'] = 'error'
            result['error'] = str(e)
            if self.verbose:
                print(f"Error scanning port {port}: {e}")
        
        return result
    
    def detect_service(self, port: int, banner: str) -> str:
        """Simple service detection based on port and banner."""
        service_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1433: 'mssql',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            6379: 'redis',
            27017: 'mongodb',
            8080: 'http',
            8443: 'https'
        }
        
        service = service_map.get(port, 'unknown')
        
        # Refine based on banner content
        banner_lower = banner.lower()
        if 'apache' in banner_lower:
            service = 'apache'
        elif 'nginx' in banner_lower:
            service = 'nginx'
        elif 'microsoft' in banner_lower or 'iis' in banner_lower:
            service = 'iis'
        elif 'openssh' in banner_lower:
            service = 'openssh'
        elif 'proftpd' in banner_lower or 'vsftpd' in banner_lower:
            service = 'ftp'
        elif 'http' in banner_lower:
            service = 'http'
            
        return service
    
    def scan_ports(self, ports: List[int], workers: int = 8) -> List[Dict[str, Any]]:
        """Scan all ports concurrently using ThreadPoolExecutor."""
        results = []
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    if self.verbose:
                        print(f"Error processing port {port}: {e}")
        
        return results