import socket
import sys

def test_domain_resolution(domain):
    """Test if we can resolve a domain to an IP address"""
    try:
        print(f"Testing domain resolution for: {domain}")
        ip_address = socket.gethostbyname(domain)
        print(f"SUCCESS: {domain} resolves to {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"ERROR: Could not resolve {domain} - {e}")
        return None

def test_port_connection(ip, port):
    """Test if we can connect to a specific port"""
    try:
        print(f"Testing connection to {ip}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            print(f"SUCCESS: Port {port} is open on {ip}")
            return True
        else:
            print(f"INFO: Port {port} is closed on {ip} (result code: {result})")
            return False
    except Exception as e:
        print(f"ERROR: Could not connect to {ip}:{port} - {e}")
        return False

if __name__ == "__main__":
    # Test with a common domain
    domain = "google.com"
    print("Connection Test Script")
    print("=====================")
    
    # Test domain resolution
    ip = test_domain_resolution(domain)
    
    if ip:
        # Test connection to port 80 (HTTP)
        test_port_connection(ip, 80)
        
        # Test connection to port 443 (HTTPS)
        test_port_connection(ip, 443)
    
    print("\nTest completed.")