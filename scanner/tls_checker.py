import socket
import ssl
from datetime import datetime
from typing import Dict, Any, Optional


class TLSChecker:
    """Handles TLS certificate validation and analysis."""
    
    def __init__(self, target: str, timeout: float, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
    
    def check_tls_certificate(self, port: int = 443) -> Dict[str, Any]:
        """Check TLS certificate details."""
        result = {
            'issuer': {},
            'subject': {},
            'expiry': None,
            'days_until_expiry': None,
            'is_expired': False,
            'is_near_expiry': False,
            'error': None
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    if cert_der:
                        # Parse certificate for more details
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        # Get certificate expiry
                        not_after = cert_obj.not_valid_after
                        now = datetime.now()
                        days_until_expiry = (not_after - now).days
                        
                        issuer = cert_obj.issuer
                        subject = cert_obj.subject
                        
                        # Extract issuer and subject information
                        issuer_dict = {}
                        for attr in issuer:
                            issuer_dict[attr.oid._name] = attr.value
                        
                        subject_dict = {}
                        for attr in subject:
                            subject_dict[attr.oid._name] = attr.value
                        
                        result.update({
                            'issuer': issuer_dict,
                            'subject': subject_dict,
                            'expiry': not_after.isoformat(),
                            'days_until_expiry': days_until_expiry,
                            'is_expired': days_until_expiry < 0,
                            'is_near_expiry': 0 <= days_until_expiry <= 30
                        })
                    elif cert:
                        # Fallback to basic certificate info
                        if cert and 'notAfter' in cert:
                            expiry_str = cert['notAfter']
                            expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                            now = datetime.now()
                            days_until_expiry = (expiry_date - now).days
                            
                            result.update({
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'expiry': expiry_date.isoformat(),
                                'days_until_expiry': days_until_expiry,
                                'is_expired': days_until_expiry < 0,
                                'is_near_expiry': 0 <= days_until_expiry <= 30
                            })
                        
        except Exception as e:
            result['error'] = f"TLS certificate check failed: {str(e)}"
            if self.verbose:
                print(f"  ⚠️  {result['error']}")
        
        return result