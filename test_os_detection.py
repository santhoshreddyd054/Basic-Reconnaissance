import socket
import platform
import subprocess

def detect_os_by_ttl(ip_address):
    """Detect OS using TTL value from ping response"""
    try:
        # Send a ping request and capture the output
        if platform.system().lower() == "windows":
            # Windows ping command
            cmd = ["ping", "-n", "1", "-w", "1000", ip_address]
        else:
            # Unix/Linux ping command
            cmd = ["ping", "-c", "1", "-W", "1", ip_address]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            # Extract TTL value from output
            output = result.stdout.lower()
            if "ttl=" in output:
                # Find TTL value
                ttl_index = output.find("ttl=")
                if ttl_index != -1:
                    ttl_str = output[ttl_index+4:ttl_index+10]  # Get characters after ttl=
                    ttl = int(ttl_str.split()[0])  # Extract the number
                    
                    # Estimate OS based on TTL with more detailed ranges
                    if 32 <= ttl <= 64:
                        return "Linux/Unix"
                    elif 65 <= ttl <= 128:
                        return "Windows"
                    elif ttl == 255:
                        return "Cisco/Network Equipment"
                    elif ttl > 128:
                        return "Possibly Windows (High TTL)"
                    elif ttl < 32:
                        return "Possibly Embedded/Limited Device"
                    else:
                        return "Unknown OS"
            else:
                return "No TTL found in ping response"
        else:
            return "Ping failed - Host may be down or blocking ICMP"
        
        return "Unknown"
    except subprocess.TimeoutExpired:
        return "Ping timeout - Host may be slow or blocking ICMP"
    except Exception as e:
        return f"Ping error: {e}"

# Test with a few known addresses
test_addresses = ["8.8.8.8", "1.1.1.1", "google.com"]

for addr in test_addresses:
    try:
        # Resolve to IP if it's a domain
        ip = socket.gethostbyname(addr)
        print(f"Testing {addr} ({ip}):")
        result = detect_os_by_ttl(ip)
        print(f"  OS Detection: {result}")
        print()
    except Exception as e:
        print(f"Error testing {addr}: {e}")