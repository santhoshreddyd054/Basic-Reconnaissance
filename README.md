# Domain Scanner

This is a Python application that takes a domain name as input and displays:
1. The IP address of the domain
2. Open ports on that domain (ports 1-1024)

## Requirements

- Python 3.x installed and added to your PATH

## How to Use

1. Open a terminal/command prompt
2. Navigate to the directory containing the script:
   ```
   cd path/to/domain_scanner
   ```
3. Run the script:
   ```
   python domain_scanner.py
   ```
4. Enter a domain name when prompted (e.g., google.com)
5. To exit the application, type 'quit'

## Features

- DNS lookup to resolve domain names to IP addresses
- Port scanning for ports 1-1024
- Concurrent scanning for improved performance
- Continuous operation - enter multiple domains without restarting

## Example Usage

```
Domain Scanner - Enter 'quit' to exit

Enter domain name: google.com

Scanning domain: google.com
Resolving IP address...
IP Address: 142.250.191.14
Scanning ports (1-1024)...

Open ports: 22, 80, 443
```
<img width="1337" height="633" alt="Screenshot 2025-11-20 183438" src="https://github.com/user-attachments/assets/885ded58-3966-4e37-8ceb-856411077888" />
