from flask import Flask, request, jsonify
import socket
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__, instance_path='E:/reconinsance/instance')

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

def scan_port_fast(ip, port):
    """Scan a single port on the given IP address with faster timeout"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # Reduced timeout for speed
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None

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

def scan_ports(ip, start_port=1, end_port=65535):
    """Scan ports on the given IP address - scanning all 65535 ports as requested"""
    open_ports = []
    
    # Use ThreadPoolExecutor for concurrent port scanning
    with ThreadPoolExecutor(max_workers=1000) as executor:  # Increased workers for full port scan
        # Submit all port scanning tasks
        future_to_port = {
            executor.submit(scan_port_fast, ip, port): port 
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
    """Detect OS using multiple methods for better accuracy - optimized for speed"""
    try:
        # Run all detection methods in parallel for speed
        with ThreadPoolExecutor(max_workers=3) as executor:
            # Submit all detection tasks using fast versions
            future_ttl = executor.submit(detect_os_by_ttl, ip_address)
            future_ports = executor.submit(detect_os_by_ports_fast, ip_address)
            future_service = executor.submit(get_service_info_fast, ip_address)
            
            # Collect results
            try:
                os_by_ttl = future_ttl.result(timeout=2)  # Add timeout
            except:
                os_by_ttl = "TTL detection timeout"
                
            try:
                os_by_ports = future_ports.result(timeout=2)  # Add timeout
            except:
                os_by_ports = "Port detection timeout"
                
            try:
                service_info = future_service.result(timeout=2)  # Add timeout
            except:
                service_info = "Service info timeout"
        
        # Combine all information
        result = f"OS Detection Results: "
        result += f"TTL-based: {os_by_ttl}; "
        result += f"Port-based: {os_by_ports}; "
        result += f"Service Info: {service_info}"
        
        return result
    except Exception as e:
        return f"Error detecting OS: {e}"

def detect_os_by_ttl(ip_address):
    """Detect OS using TTL value from ping response - optimized for speed"""
    try:
        # Send a ping request and capture the output
        if platform.system().lower() == "windows":
            # Windows ping command with shorter timeout
            cmd = ["ping", "-n", "1", "-w", "500", ip_address]
        else:
            # Unix/Linux ping command with shorter timeout
            cmd = ["ping", "-c", "1", "-W", "1", ip_address]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)  # Reduced timeout
        
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

def get_service_info_fast(ip_address):
    """Grab banners from common services to get more OS details - optimized for speed"""
    try:
        service_details = []
        
        # Try to get banner from common services with faster timeout
        services_to_check = [
            (80, "HTTP"),
            (443, "HTTPS"),
            (22, "SSH"),
            (23, "Telnet")
        ]
        
        for port, service_name in services_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Reduced timeout for speed
                result = sock.connect_ex((ip_address, port))
                
                if result == 0:
                    # Try to grab banner
                    if port in [80, 443]:
                        # For web servers, send HTTP request
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    else:
                        # For other services, try to read banner
                        sock.send(b"\n")
                    
                    # Read response with timeout
                    try:
                        banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
                        if banner:
                            # Clean up banner for display
                            banner_lines = banner.split('\n')
                            first_line = banner_lines[0][:30] + ("..." if len(banner_lines[0]) > 30 else "")
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

def detect_os_by_ports_fast(ip_address):
    """Detect OS based on open ports with enhanced heuristics - optimized for speed"""
    try:
        # Scan of common ports with more detailed analysis - reduced set for speed
        port_info = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            23: "Telnet",
            3389: "RDP (Windows)",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL (Windows)"
        }
        
        open_ports = {}
        
        # Check which ports are open with faster timeout
        for port, service in port_info.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)  # Even shorter timeout for speed
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
        
        # Web server indicators
        web_ports = [80, 443]
        web_open = [port for port in web_ports if port in open_ports]
        if web_open:
            os_hints.append("Web Server")
        
        # Database server indicators
        db_ports = [3306, 5432, 1433]
        db_open = [port for port in db_ports if port in open_ports]
        if db_open:
            os_hints.append("Database Server")
        
        if os_hints:
            return f"{', '.join(os_hints)} - Open ports: {', '.join([f'{p}({s})' for p, s in open_ports.items()])}"
        else:
            return f"Open ports: {', '.join([f'{p}({s})' for p, s in open_ports.items()])} - OS detection inconclusive"
        
    except Exception as e:
        return f"Port detection error: {e}"

@app.route('/')
def index():
    return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Domain Scanner</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #1a365d;
            --primary-dark: #0f1c2e;
            --primary-light: #2a4a7c;
            --secondary: #2d3748;
            --accent: #4299e1;
            --success: #38a169;
            --danger: #e53e3e;
            --warning: #dd6b20;
            --info: #3182ce;
            --dark: #1a202c;
            --light: #2d3748;
            --gray: #4a5568;
            --border: #2d3748;
            --text-primary: #f7fafc;
            --text-secondary: #cbd5e0;
            --card-bg: #1e293b;
            --card-border: #2d3748;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #0c1220 50%, #0a0f1a 100%);
            min-height: 100vh;
            padding: 0;
            color: var(--text-primary);
            background-attachment: fixed;
            margin: 0;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        header {
            text-align: center;
            padding: 30px 0;
            margin-bottom: 30px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            border: 1px solid var(--card-border);
        }
        
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .logo i {
            font-size: 3rem;
            color: var(--accent);
            text-shadow: 0 0 15px rgba(66, 153, 225, 0.6);
        }
        
        h1 {
            font-size: 2.8rem;
            font-weight: 700;
            color: var(--text-primary);
            letter-spacing: -0.5px;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
            margin: 0;
        }
        
        .subtitle {
            font-size: 1.2rem;
            color: var(--text-secondary);
            max-width: 700px;
            margin: 0 auto;
            line-height: 1.7;
            font-weight: 300;
        }
        
        .scanner-card {
            background: var(--card-bg);
            border-radius: 16px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
            padding: 40px;
            margin-bottom: 30px;
            transition: all 0.3s ease;
            border: 1px solid var(--card-border);
            position: relative;
            overflow: hidden;
        }
        
        .scanner-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-light), var(--accent), var(--primary-light));
        }
        
        .input-group {
            margin-bottom: 30px;
        }
        
        label {
            display: block;
            margin-bottom: 12px;
            font-weight: 600;
            color: var(--text-primary);
            font-size: 1.1rem;
            letter-spacing: 0.5px;
        }
        
        .input-wrapper {
            position: relative;
            margin-bottom: 10px;
        }
        
        .input-wrapper i {
            position: absolute;
            left: 18px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--accent);
            font-size: 1.2rem;
        }
        
        input[type="text"] {
            width: 100%;
            padding: 18px 20px 18px 55px;
            border: 2px solid var(--border);
            border-radius: 12px;
            font-size: 1.1rem;
            transition: all 0.3s ease;
            background-color: var(--secondary);
            color: var(--text-primary);
            font-weight: 400;
            box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        input[type="text"]:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.3);
            background-color: var(--primary-dark);
        }
        
        button {
            background: linear-gradient(135deg, var(--primary-light) 0%, var(--primary) 100%);
            color: white;
            padding: 18px 32px;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 1.1rem;
            font-weight: 600;
            width: 100%;
            transition: all 0.3s ease;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.3);
            letter-spacing: 0.5px;
            text-transform: uppercase;
            font-size: 1rem;
            position: relative;
            overflow: hidden;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.4);
            background: linear-gradient(135deg, var(--accent) 0%, var(--primary-light) 100%);
        }
        
        button:disabled {
            background: var(--gray);
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            display: none;
            background: var(--card-bg);
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid var(--card-border);
        }
        
        .spinner {
            border: 4px solid rgba(66, 153, 225, 0.3);
            border-top: 4px solid var(--accent);
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 25px;
            box-shadow: 0 0 15px rgba(66, 153, 225, 0.5);
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .result {
            display: none;
            background: var(--card-bg);
            border-radius: 16px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.4);
            padding: 0;
            margin-top: 20px;
            animation: fadeIn 0.5s ease;
            border: 1px solid var(--card-border);
            overflow: hidden;
            position: relative;
        }
        
        .result::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--success), var(--accent), var(--success));
        }
        
        .result.error::before {
            background: linear-gradient(90deg, var(--danger), var(--warning), var(--danger));
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .result-header {
            display: flex;
            align-items: center;
            gap: 20px;
            padding: 25px 30px;
            background: var(--primary-dark);
            border-bottom: 1px solid var(--card-border);
        }
        
        .result-header i {
            font-size: 2rem;
            color: var(--accent);
        }
        
        .result.success .result-header i {
            color: var(--success);
        }
        
        .result.error .result-header i {
            color: var(--danger);
        }
        
        .result h2 {
            font-size: 1.8rem;
            font-weight: 700;
            margin: 0;
            color: var(--text-primary);
        }
        
        .result-content {
            display: grid;
            gap: 25px;
            padding: 30px;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        }
        
        .info-card {
            background: var(--secondary);
            border-radius: 12px;
            padding: 25px;
            border: 1px solid var(--card-border);
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease;
        }
        
        .info-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.3);
            border-color: var(--accent);
        }
        
        .info-card h3 {
            font-size: 1.3rem;
            margin-bottom: 20px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 12px;
            font-weight: 600;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border);
        }
        
        .info-card h3 i {
            color: var(--accent);
            font-size: 1.4rem;
        }
        
        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 15px 0;
            border-bottom: 1px solid var(--border);
        }
        
        .info-item:last-child {
            border-bottom: none;
        }
        
        .info-label {
            font-weight: 600;
            color: var(--text-secondary);
            min-width: 150px;
        }
        
        .info-value {
            font-weight: 500;
            color: var(--text-primary);
            text-align: right;
            word-break: break-all;
            flex: 1;
            margin-left: 20px;
        }
        
        .ports-container {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 15px;
        }
        
        .port {
            background: linear-gradient(135deg, var(--primary-light) 0%, var(--primary) 100%);
            color: white;
            padding: 10px 18px;
            border-radius: 25px;
            font-size: 0.9rem;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            box-shadow: 0 3px 8px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            border: 1px solid var(--card-border);
        }
        
        .port:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 12px rgba(0, 0, 0, 0.4);
            background: linear-gradient(135deg, var(--accent) 0%, var(--primary-light) 100%);
        }
        
        footer {
            text-align: center;
            padding: 30px 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: auto;
            background: var(--primary-dark);
            border-radius: 12px;
            margin-top: 30px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            header {
                padding: 20px 0;
            }
            
            h1 {
                font-size: 2.2rem;
            }
            
            .scanner-card {
                padding: 25px;
            }
            
            .result-content {
                grid-template-columns: 1fr;
                padding: 20px;
            }
            
            .result-header {
                padding: 20px;
                gap: 15px;
            }
            
            .info-card {
                padding: 20px;
            }
        }
        
        @media (max-width: 480px) {
            .container {
                padding: 10px;
            }
            
            h1 {
                font-size: 1.8rem;
            }
            
            .subtitle {
                font-size: 1rem;
            }
            
            .scanner-card {
                padding: 20px;
            }
            
            .port {
                padding: 8px 15px;
                font-size: 0.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <div>
                    <h1>ENTERPRISE DOMAIN SCANNER</h1>
                    <p class="subtitle">Advanced Network Intelligence & Reconnaissance Platform</p>
                </div>
            </div>
        </header>
        
        <main>
            <div class="scanner-card">
                <div class="input-group">
                    <label for="input">TARGET IDENTIFICATION</label>
                    <div class="input-wrapper">
                        <i class="fas fa-bullseye"></i>
                        <input type="text" id="input" placeholder="Enter domain (e.g., example.com) or IP address (e.g., 192.168.1.1)">
                    </div>
                </div>
                
                <button id="scan-btn">
                    <i class="fas fa-search"></i> INITIATE COMPREHENSIVE SCAN
                </button>
            </div>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <h3>PERFORMING ADVANCED NETWORK ANALYSIS</h3>
                <p><i class="fas fa-circle-notch fa-spin"></i> Scanning ports, detecting OS, and gathering intelligence...</p>
                <p style="margin-top: 15px; font-size: 0.9rem; color: var(--text-secondary);"><i class="fas fa-info-circle"></i> Please wait up to 1 minute for complete results</p>
            </div>
            
            <div class="result" id="result"></div>
        </main>
        
        <footer>
            <p><i class="fas fa-lock"></i> ENTERPRISE DOMAIN SCANNER &copy; 2025 | SECURE NETWORK INTELLIGENCE PLATFORM</p>
            <p style="margin-top: 10px; font-size: 0.9rem;"><i class="fas fa-info-circle"></i> NEED MORE HELP: <a href="mailto:santhoshreddy054@gmail.com" style="color: var(--accent); text-decoration: none;">santhoshreddy054@gmail.com</a></p>
            <p style="margin-top: 5px; font-size: 0.8rem; color: var(--text-secondary);"><i class="fas fa-clock"></i> NOTE: Please wait up to 1 minute for complete results</p>
        </footer>
    </div>

    <script>
        document.getElementById('scan-btn').addEventListener('click', scanDomain);
        document.getElementById('input').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                scanDomain();
            }
        });

        async function scanDomain() {
            const inputElement = document.getElementById('input');
            const input = inputElement.value.trim();
            const scanBtn = document.getElementById('scan-btn');
            const loading = document.getElementById('loading');
            const result = document.getElementById('result');
            
            if (!input) {
                showError('VALIDATION ERROR: Please enter a domain name or IP address');
                return;
            }
            
            // Disable button and show loading
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> INITIATING SCAN...';
            loading.style.display = 'block';
            result.style.display = 'none';
            
            try {
                // Determine if input is IP address or domain
                const isIP = /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(input);
                
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({input: input, type: isIP ? 'ip' : 'domain'})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showSuccess(data);
                } else {
                    showError(`SCAN ERROR: ${data.error}`);
                }
            } catch (error) {
                showError(`NETWORK ERROR: ${error.message || 'Failed to connect to scanning service'}`);
            } finally {
                // Re-enable button and hide loading
                scanBtn.disabled = false;
                scanBtn.innerHTML = '<i class="fas fa-search"></i> INITIATE COMPREHENSIVE SCAN';
                loading.style.display = 'none';
            }
        }
        
        function showSuccess(data) {
            const result = document.getElementById('result');
            result.className = 'result success';
            
            // Format open ports
            let portsHtml = '<div class="ports-container">';
            if (data.open_ports && data.open_ports.length > 0) {
                data.open_ports.forEach(port => {
                    portsHtml += `<span class="port"><i class="fas fa-plug"></i> ${port}</span>`;
                });
            } else {
                portsHtml += '<span class="port"><i class="fas fa-times"></i> NO OPEN PORTS DETECTED</span>';
            }
            portsHtml += '</div>';
            
            // Format OS details
            let osDetails = data.os_details || 'Not detected';
            if (typeof osDetails === 'object') {
                osDetails = JSON.stringify(osDetails, null, 2);
            }
            
            // Format service info
            let serviceInfo = data.service_info || 'No service information available';
            
            result.innerHTML = `
                <div class="result-header">
                    <i class="fas fa-shield-alt"></i>
                    <h2>COMPREHENSIVE SCAN RESULTS</h2>
                </div>
                <div class="result-content">
                    <div class="info-card">
                        <h3><i class="fas fa-server"></i> TARGET IDENTIFICATION</h3>
                        <div class="info-item">
                            <span class="info-label">Domain:</span>
                            <span class="info-value">${data.domain || 'N/A'}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">IP Address:</span>
                            <span class="info-value">${data.ip_address || 'N/A'}</span>
                        </div>
                    </div>
                    
                    <div class="info-card">
                        <h3><i class="fas fa-microchip"></i> SYSTEM ANALYSIS</h3>
                        <div class="info-item">
                            <span class="info-label">Operating System:</span>
                            <span class="info-value">${osDetails}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Service Details:</span>
                            <span class="info-value">${serviceInfo}</span>
                        </div>
                    </div>
                    
                    <div class="info-card">
                        <h3><i class="fas fa-plug"></i> NETWORK VULNERABILITY ASSESSMENT</h3>
                        <div class="info-item">
                            <span class="info-label">Open Ports Detected:</span>
                            <span class="info-value">${portsHtml}</span>
                        </div>
                    </div>
                </div>
            `;
            result.style.display = 'block';
            
            // Scroll to results
            result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
        
        function showError(message) {
            const result = document.getElementById('result');
            result.className = 'result error';
            result.innerHTML = `
                <div class="result-header">
                    <i class="fas fa-exclamation-triangle"></i>
                    <h2>SCAN OPERATION FAILED</h2>
                </div>
                <div class="result-content">
                    <div class="info-card">
                        <h3><i class="fas fa-bug"></i> ERROR DIAGNOSTICS</h3>
                        <div class="info-item">
                            <span class="info-label">Error Code:</span>
                            <span class="info-value">${message}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Timestamp:</span>
                            <span class="info-value">${new Date().toLocaleString()}</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Recommendation:</span>
                            <span class="info-value">Verify target accessibility and network connectivity</span>
                        </div>
                    </div>
                </div>
            `;
            result.style.display = 'block';
            
            // Scroll to results
            result.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    </script>
</body>
</html>
    '''


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    user_input = data.get('input', '').strip()
    input_type = data.get('type', 'domain')
    
    if not user_input:
        return jsonify({'error': 'Please provide a domain name or IP address'}), 400
    
    if input_type == 'ip':
        # Handle IP address input
        ip_address = user_input
        
        # Get domain name (reverse DNS lookup)
        domain_name = get_domain_name(ip_address)
        
        # Get additional service info
        service_info = get_service_info(ip_address)
        
        # Detect OS
        os_details = detect_os(ip_address)
        
        # Scan ports
        open_ports = scan_ports(ip_address)
        
        return jsonify({
            'domain': domain_name,
            'ip_address': ip_address,
            'os_details': os_details,
            'service_info': service_info,
            'open_ports': open_ports
        })
    else:
        # Handle domain name input
        domain = user_input
        
        # Get IP address
        ip_address = get_ip_address(domain)
        
        # If IP resolution failed, return error
        if "Error" in str(ip_address):
            return jsonify({'error': ip_address}), 400
        
        # Get additional service info
        service_info = get_service_info(ip_address)
        
        # Detect OS
        os_details = detect_os(ip_address)
        
        # Scan ports
        open_ports = scan_ports(ip_address)
        
        return jsonify({
            'domain': domain,
            'ip_address': ip_address,
            'os_details': os_details,
            'service_info': service_info,
            'open_ports': open_ports
        })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)