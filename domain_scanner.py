import socket
import platform
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_ip_address(domain):
    """Get IP address for a given domain name"""
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        return f"Error resolving domain: {e}"

def get_domain_name(ip_address):
    """Get domain name for a given IP address (reverse DNS lookup)"""
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror as e:
        return f"Error resolving IP to domain: {e}"

def scan_port(ip, port):
    """Scan a single port on the given IP address"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None

def scan_ports(ip, start_port=1, end_port=1024):
    """Scan ports on the given IP address"""
    open_ports = []
    
    # Use ThreadPoolExecutor for concurrent port scanning
    with ThreadPoolExecutor(max_workers=100) as executor:
        # Submit all port scanning tasks
        future_to_port = {
            executor.submit(scan_port, ip, port): port 
            for port in range(start_port, end_port + 1)
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
            except Exception:
                pass
    
    return sorted(open_ports)

def detect_os(ip_address):
    """Detect OS using multiple methods for better accuracy"""
    try:
        # Method 1: TTL-based detection
        os_by_ttl = detect_os_by_ttl(ip_address)
        
        # Method 2: Port-based detection
        os_by_ports = detect_os_by_ports(ip_address)
        
        # Method 3: Service banner grabbing (if common service ports are open)
        service_info = get_service_info(ip_address)
        
        # Combine all information
        result = f"OS Detection Results:\n"
        result += f"  TTL-based: {os_by_ttl}\n"
        result += f"  Port-based: {os_by_ports}\n"
        result += f"  Service Info: {service_info}"
        
        return result
    except Exception as e:
        return f"Error detecting OS: {e}"

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

def detect_os_by_ports(ip_address):
    """Detect OS based on open ports with enhanced heuristics"""
    try:
        # Scan of common ports with more detailed analysis
        port_info = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP (Windows)",
            5900: "VNC",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL (Windows)",
            1521: "Oracle DB",
            8080: "HTTP-Alt"
        }
        
        open_ports = {}
        
        # Check which ports are open
        for port, service in port_info.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Short timeout
            result = sock.connect_ex((ip_address, port))
            sock.close()
            if result == 0:
                open_ports[port] = service
        
        if not open_ports:
            return "No common ports open or host is filtering"
        
        # Enhanced heuristics based on port combinations
        os_hints = []
        
        # Windows indicators
        if 3389 in open_ports:  # RDP
            os_hints.append("Windows (RDP detected)")
        if 1433 in open_ports:  # MSSQL
            os_hints.append("Windows (MSSQL detected)")
            
        # Linux/Unix indicators
        if 22 in open_ports and 3389 not in open_ports:  # SSH but no RDP
            os_hints.append("Linux/Unix (SSH detected)")
        if 5432 in open_ports:  # PostgreSQL
            os_hints.append("Linux/Unix (PostgreSQL detected)")
            
        # Network device indicators
        if 23 in open_ports and 22 not in open_ports and 3389 not in open_ports:
            os_hints.append("Network Device (Telnet detected)")
        if 53 in open_ports and len(open_ports) <= 3:  # Primarily DNS
            os_hints.append("Network Device (DNS server)")
            
        # Web server indicators
        web_ports = [80, 443, 8080]
        web_open = [port for port in web_ports if port in open_ports]
        if web_open and len(open_ports) <= 3:
            os_hints.append("Web Server (Limited services)")
        elif web_open:
            os_hints.append("Web Server (Multiple services)")
            
        # Database server indicators
        db_ports = [3306, 5432, 1433, 1521]
        db_open = [port for port in db_ports if port in open_ports]
        if db_open:
            os_hints.append("Database Server")
            
        if os_hints:
            return f"{', '.join(os_hints)} - Open ports: {', '.join([f'{p}({s})' for p, s in open_ports.items()])}"
        else:
            return f"Open ports: {', '.join([f'{p}({s})' for p, s in open_ports.items()])} - OS detection inconclusive"
            
    except Exception as e:
        return f"Port detection error: {e}"

def get_service_info(ip_address):
    """Grab banners from common services to get more OS details"""
    try:
        service_details = []
        
        # Try to get banner from common services
        services_to_check = [
            (22, "SSH"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (23, "Telnet"),
            (21, "FTP")
        ]
        
        for port, service_name in services_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # Longer timeout for banner grabbing
                result = sock.connect_ex((ip_address, port))
                
                if result == 0:
                    # Try to grab banner
                    if port in [80, 443]:
                        # For web servers, send HTTP request
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        # For other services, try to read banner
                        sock.send(b"\n")
                    
                    # Read response
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        if banner:
                            # Clean up banner for display
                            banner_lines = banner.split('\n')
                            first_line = banner_lines[0][:50] + ("..." if len(banner_lines[0]) > 50 else "")
                            service_details.append(f"{service_name}({port}): {first_line}")
                        else:
                            service_details.append(f"{service_name}({port}): No banner")
                    except:
                        service_details.append(f"{service_name}({port}): Banner read failed")
                
                sock.close()
            except Exception:
                # Skip this service if we can't get a banner
                pass
        
        if service_details:
            return "; ".join(service_details)
        else:
            return "No service banners captured"
            
    except Exception as e:
        return f"Banner grabbing error: {e}"

def scan_domain(domain):
    """Scan a domain for IP address, OS details, and open ports"""
    print(f"\nScanning domain: {domain}")
    
    # Get IP address
    print("Resolving IP address...")
    ip_address = get_ip_address(domain)
    print(f"IP Address: {ip_address}")
    
    # If IP resolution failed, exit
    if "Error" in str(ip_address):
        return
    
    # Detect OS
    print("Detecting OS...")
    os_details = detect_os(ip_address)
    print(f"OS Details:\n{os_details}")
    
    # Scan ports
    print("Scanning ports (1-1024)...\n")
    open_ports = scan_ports(ip_address)
    
    if open_ports:
        print(f"Open ports: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found in range 1-1024")

def scan_ip_address(ip_address):
    """Scan an IP address for domain name, OS details, and open ports"""
    print(f"\nScanning IP address: {ip_address}")
    
    # Get domain name (reverse DNS lookup)
    print("Resolving domain name...")
    domain_name = get_domain_name(ip_address)
    print(f"Domain Name: {domain_name}")
    
    # If domain resolution failed, continue with other scans
    
    # Detect OS
    print("Detecting OS...")
    os_details = detect_os(ip_address)
    print(f"OS Details:\n{os_details}")
    
    # Scan ports
    print("Scanning ports (1-1024)...\n")
    open_ports = scan_ports(ip_address)
    
    if open_ports:
        print(f"Open ports: {', '.join(map(str, open_ports))}")
    else:
        print("No open ports found in range 1-1024")

def is_valid_ip(ip):
    """Check if the input is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def main():
    print("Domain Scanner - Enter 'quit' to exit")
    print("Enter a domain name to get IP address and scan ports")
    print("Or enter an IP address to get domain name and scan ports")
    print("Note: OS detection uses TTL values and may not always be accurate")
    
    while True:
        user_input = input("\nEnter domain name or IP address: ").strip()
        
        if user_input.lower() == 'quit':
            print("Goodbye!")
            break
        
        if not user_input:
            print("Please enter a valid domain name or IP address.")
            continue
        
        if is_valid_ip(user_input):
            scan_ip_address(user_input)
        else:
            scan_domain(user_input)

if __name__ == "__main__":
    main()