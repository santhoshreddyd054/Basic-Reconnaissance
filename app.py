from flask import Flask, render_template, request, jsonify
import socket
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

app = Flask(__name__, instance_path='E:/reconinsance/instance')

def get_ip_address(domain):
    """Get IP address for a given domain name"""
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror as e:
        return f"Error resolving domain: {e}"

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

@app.route('/')
def index():
    return render_template('index.html')

def detect_os(ip_address):
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
                    
                    # Estimate OS based on TTL
                    if ttl <= 64:
                        return "Linux/Unix"
                    elif ttl <= 128:
                        return "Windows"
                    else:
                        return "Unknown"
        
        return "Unknown"
    except Exception as e:
        return f"Error detecting OS: {e}"

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Please provide a domain name'}), 400
    
    # Get IP address
    ip_address = get_ip_address(domain)
    
    # If IP resolution failed, return error
    if "Error" in str(ip_address):
        return jsonify({'error': ip_address}), 400
    
    # Detect OS
    os_details = detect_os(ip_address)
    
    # Scan ports
    open_ports = scan_ports(ip_address)
    
    return jsonify({
        'domain': domain,
        'ip_address': ip_address,
        'os_details': os_details,
        'open_ports': open_ports
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)