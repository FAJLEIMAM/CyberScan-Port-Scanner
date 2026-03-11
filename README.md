CyberScan – Educational Cybersecurity Port Scanner
CyberScan is a lightweight Python-based multithreaded port scanner designed for cybersecurity learning, research, and network reconnaissance. The tool scans a target host to identify open ports, running services, and potential security risks.

⚠ Important: This tool is intended strictly for educational and authorized security testing purposes. Only scan systems you own or have explicit permission to test.

Author
Fajle Imam

Features
Multithreaded port scanning
TCP connect scanning
Service identification
Security risk classification
Optional banner grabbing
JSON report generation
Preset scan profiles
Colored terminal output
Installation
git clone https://github.com/yourusername/cyberscan-port-scanner.git cd cyberscan-port-scanner pip install -r requirements.txt

Usage
python port_scanner.py localhost python port_scanner.py example.com -p 80,443,8080 python port_scanner.py 192.168.1.1 -p 1-1024 python port_scanner.py scanme.nmap.org --preset quick

Ethical Notice
Only scan systems you own or have explicit permission to test.

License
MIT License
