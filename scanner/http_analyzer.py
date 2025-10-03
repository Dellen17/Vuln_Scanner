import requests
from requests.exceptions import RequestException
from typing import Dict, Any, List
import urllib3

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPAnalyzer:
    """Handles HTTP security header analysis."""
    
    def __init__(self, target: str, timeout: float, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
    
    def check_http_headers(self, port: int, scheme: str = 'http') -> Dict[str, Any]:
        """Check HTTP security headers for a given port and scheme."""
        url = f"{scheme}://{self.target}:{port}"
        result = {
            'url': url,
            'status_code': None,
            'headers_found': {},
            'headers_missing': [],
            'error': None
        }
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            headers = dict(response.headers)
            
            security_headers = {
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security') if scheme == 'https' else 'N/A (HTTP)',
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy')
            }
            
            result['status_code'] = response.status_code
            result['headers_found'] = {k: v for k, v in security_headers.items() if v and v != 'N/A (HTTP)'}
            result['headers_missing'] = [k for k, v in security_headers.items() if not v or v == 'N/A (HTTP)']
            
        except RequestException as e:
            result['error'] = f"HTTP check failed for {url}: {str(e)}"
            if self.verbose:
                print(f"  ⚠️  {result['error']}")
        
        return result