import socket
import ipaddress
from urllib.parse import urlparse

class DNSValidator:
    """
    Validates target URLs to prevent scanning of private/internal networks
    and ensures DNS resolution works before scanning.
    """
    
    @staticmethod
    def get_hostname(url: str) -> str:
        """Extract hostname from URL"""
        try:
            parsed = urlparse(url)
            # If no scheme is provided, urlparse might put everything in path
            if not parsed.netloc:
                if "://" not in url:
                    parsed = urlparse(f"http://{url}")
            
            hostname = parsed.netloc.split(':')[0] # Remove port
            return hostname
        except Exception:
            return url

    @staticmethod
    def resolve_and_validate(url: str, allow_private: bool = False) -> str:
        """
        Resolve URL to IP and check if it is allowed.
        Returns the resolved IP if valid, raises ValueError if blocked.
        """
        hostname = DNSValidator.get_hostname(url)
        
        # 1. Resolve to IP
        try:
            ip_str = socket.gethostbyname(hostname)
        except socket.gaierror:
            raise ValueError(f"DNS resolution failed for {hostname}")
            
        # 2. Check IP type
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"Invalid IP address resolved: {ip_str}")
            
        if not allow_private:
            if ip_obj.is_private:
                raise ValueError(f"Target resolves to private IP: {ip_str}")
            if ip_obj.is_loopback:
                raise ValueError(f"Target resolves to loopback IP: {ip_str}")
            if ip_obj.is_reserved:
                raise ValueError(f"Target resolves to reserved IP: {ip_str}")
            if ip_obj.is_multicast:
                raise ValueError(f"Target resolves to multicast IP: {ip_str}")
                
        return ip_str
