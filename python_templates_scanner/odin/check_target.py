"""
CheckTarget - Represents a target to be checked
"""


class CheckTarget:
    """Represents a target system to be checked for vulnerabilities."""
    
    def __init__(self, ip: str, port: int, fqdn: str, ssl: bool = False):
        """
        Initialize a CheckTarget.
        
        Args:
            ip: IP address of the target
            port: Port number of the target
            fqdn: Fully qualified domain name of the target
            ssl: Whether SSL/TLS is enabled (default: False)
        """
        self.ip = ip
        self.port = port
        self.fqdn = fqdn
        self.ssl = ssl
    
    def as_url(self, protocol: str = None) -> str:
        """
        Convert the target to a URL string.
        
        Args:
            protocol: Protocol to use ('http' or 'https'). 
                     If None, uses 'https' if ssl is True, otherwise 'http'
        
        Returns:
            URL string in the format protocol://fqdn:port or protocol://ip:port
        """
        if protocol is None:
            protocol = 'https' if self.ssl else 'http'
        
        # Prefer FQDN if available, otherwise use IP
        host = self.fqdn if self.fqdn else self.ip
        
        # Standard ports don't need to be included in URL
        if (protocol == 'http' and self.port == 80) or (protocol == 'https' and self.port == 443):
            return f'{protocol}://{host}'
        
        return f'{protocol}://{host}:{self.port}'
    
    def __repr__(self):
        return f'CheckTarget(ip={self.ip}, port={self.port}, fqdn={self.fqdn}, ssl={self.ssl})'

