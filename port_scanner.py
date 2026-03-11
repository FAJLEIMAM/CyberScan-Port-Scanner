#!/usr/bin/env python3
"""
CyberScan - Educational Port Scanner
A Python-based port scanner for cybersecurity learning.
Scans target systems to identify open ports and running services.

EDUCATIONAL USE ONLY - Only scan systems you own or have explicit permission to scan.
"""

import socket
import sys
import time
import threading
import argparse
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─────────────────────────────────────────────
# Known service fingerprints (port → service)
# ─────────────────────────────────────────────
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE/IPSec",
    514: "Syslog",
    515: "LPD/LPR",
    587: "SMTP Submission",
    631: "IPP (Printing)",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MS SQL Server",
    1521: "Oracle DB",
    1723: "PPTP VPN",
    2049: "NFS",
    2181: "ZooKeeper",
    2375: "Docker (unsecured)",
    2376: "Docker (TLS)",
    3306: "MySQL",
    3389: "RDP",
    4369: "Erlang Port Mapper",
    5000: "Flask/Dev Server",
    5432: "PostgreSQL",
    5672: "RabbitMQ AMQP",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes API",
    7000: "Cassandra",
    8080: "HTTP Alt / Tomcat",
    8443: "HTTPS Alt",
    8888: "Jupyter Notebook",
    9000: "SonarQube / PHP-FPM",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch Cluster",
    10250: "Kubernetes Kubelet",
    11211: "Memcached",
    15672: "RabbitMQ Management",
    27017: "MongoDB",
    27018: "MongoDB Shard",
    27019: "MongoDB Config",
    50070: "Hadoop NameNode",
}

# Security risk levels
RISK_MAP = {
    21: ("HIGH", "FTP transmits data in plaintext"),
    22: ("LOW", "SSH is encrypted — check for weak creds"),
    23: ("CRITICAL", "Telnet is unencrypted and obsolete"),
    25: ("MEDIUM", "SMTP may allow email relay abuse"),
    53: ("MEDIUM", "DNS — check for zone transfer & amplification"),
    80: ("LOW", "HTTP — check for insecure content"),
    135: ("HIGH", "MS RPC — common attack surface"),
    139: ("HIGH", "NetBIOS — legacy, often exploited"),
    143: ("MEDIUM", "IMAP — may expose credentials"),
    161: ("HIGH", "SNMP — often misconfigured with public community"),
    443: ("INFO", "HTTPS — verify certificate validity"),
    445: ("HIGH", "SMB — EternalBlue, WannaCry vector"),
    1433: ("HIGH", "MS SQL — often targeted by attackers"),
    1521: ("HIGH", "Oracle DB — default creds are common"),
    2375: ("CRITICAL", "Docker daemon without TLS — full host takeover risk"),
    3306: ("HIGH", "MySQL — avoid exposing to internet"),
    3389: ("HIGH", "RDP — brute-force and BlueKeep vector"),
    5432: ("HIGH", "PostgreSQL — avoid exposing to internet"),
    5900: ("HIGH", "VNC — often no auth or weak passwords"),
    6379: ("CRITICAL", "Redis — often no auth, RCE risk"),
    8080: ("MEDIUM", "HTTP Alt — check for admin panels"),
    8888: ("HIGH", "Jupyter — often no auth, RCE risk"),
    9200: ("HIGH", "Elasticsearch — often no auth, data exposure"),
    11211: ("HIGH", "Memcached — DDoS amplification vector"),
    27017: ("HIGH", "MongoDB — often no auth, data exposure"),
}

COLORS = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
    "red":     "\033[91m",
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "blue":    "\033[94m",
    "magenta": "\033[95m",
    "cyan":    "\033[96m",
    "white":   "\033[97m",
    "bg_red":  "\033[41m",
    "bg_green":"\033[42m",
}

def c(color, text):
    """Apply color to text."""
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"

def print_banner():
    banner = f"""
{c('cyan', '╔══════════════════════════════════════════════════════════╗')}
{c('cyan', '║')}  {c('bold', c('green', '  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗'))}  {c('cyan', '║')}
{c('cyan', '║')}  {c('bold', c('green', ' ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝'))}  {c('cyan', '║')}
{c('cyan', '║')}  {c('bold', c('green', ' ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗'))}  {c('cyan', '║')}
{c('cyan', '║')}  {c('bold', c('green', ' ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║'))}  {c('cyan', '║')}
{c('cyan', '║')}  {c('bold', c('green', ' ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║'))}  {c('cyan', '║')}
{c('cyan', '║')}  {c('bold', c('green', '  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝'))}  {c('cyan', '║')}
{c('cyan', '║')}                                                            {c('cyan', '║')}
{c('cyan', '║')}   {c('yellow', '⚡ Educational Port Scanner — CyberSecurity Learning')}   {c('cyan', '║')}
{c('cyan', '║')}   {c('dim', '⚠  Only scan systems you own or have permission to scan')}  {c('cyan', '║')}
{c('cyan', '╚══════════════════════════════════════════════════════════╝')}
"""
    print(banner)

def resolve_target(target):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror as e:
        print(c('red', f"  [!] Cannot resolve host '{target}': {e}"))
        sys.exit(1)

def grab_banner(ip, port, timeout=2):
    """Attempt to grab a service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        
        # Send HTTP request for web ports
        if port in (80, 8080, 8000, 8888):
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 22:
            pass  # SSH sends banner automatically
        else:
            s.send(b"\r\n")
        
        banner = s.recv(1024).decode('utf-8', errors='replace').strip()
        s.close()
        
        # Truncate and clean
        banner = banner.split('\n')[0][:80]
        return banner if banner else None
    except Exception:
        return None

def scan_port(ip, port, timeout=1, grab_banners=False):
    """Scan a single port and return result dict."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        
        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            risk, note = RISK_MAP.get(port, ("INFO", "No specific risk noted"))
            banner = grab_banner(ip, port) if grab_banners else None
            return {
                "port": port,
                "state": "open",
                "service": service,
                "risk": risk,
                "note": note,
                "banner": banner,
            }
    except socket.error:
        pass
    return None

def risk_color(level):
    colors = {
        "CRITICAL": "red",
        "HIGH":     "yellow",
        "MEDIUM":   "magenta",
        "LOW":      "blue",
        "INFO":     "cyan",
    }
    return colors.get(level, "white")

def risk_icon(level):
    icons = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🔵",
        "INFO":     "⚪",
    }
    return icons.get(level, "⚪")

def print_open_port(result):
    port    = result["port"]
    service = result["service"]
    risk    = result["risk"]
    note    = result["note"]
    banner  = result.get("banner")
    icon    = risk_icon(risk)
    rc      = risk_color(risk)

    print(f"  {c('green', '►')} {c('bold', str(port).rjust(5))}/tcp   "
          f"{c('green', 'OPEN')}   "
          f"{c('cyan', service.ljust(22))} "
          f"{icon} {c(rc, risk.ljust(8))}  "
          f"{c('dim', note)}")
    
    if banner:
        print(f"           {c('dim', '│')}  {c('yellow', '⤷ Banner:')} {c('white', banner)}")

def parse_port_range(port_str):
    """Parse port range string like '1-1024' or '80,443,8080'."""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def run_scan(target, ports, timeout=1, threads=100, grab_banners=False, output_file=None):
    """Main scan routine."""
    print_banner()
    
    ip = resolve_target(target)
    start_time = datetime.now()
    
    print(f"  {c('bold', 'Target')}   : {c('cyan', target)} ({c('yellow', ip)})")
    print(f"  {c('bold', 'Ports')}    : {c('white', str(len(ports)))} ports to scan")
    print(f"  {c('bold', 'Threads')}  : {c('white', str(threads))}")
    print(f"  {c('bold', 'Timeout')}  : {c('white', str(timeout))}s per port")
    print(f"  {c('bold', 'Banners')}  : {c('green', 'enabled') if grab_banners else c('dim', 'disabled')}")
    print(f"  {c('bold', 'Started')}  : {c('dim', start_time.strftime('%Y-%m-%d %H:%M:%S'))}")
    print()
    print(c('dim', '  ' + '─' * 80))
    print(f"  {'PORT':<10} {'STATE':<8} {'SERVICE':<24} {'RISK':<12} NOTES")
    print(c('dim', '  ' + '─' * 80))
    
    open_ports = []
    scanned = 0
    lock = threading.Lock()

    def scan_and_collect(port):
        nonlocal scanned
        result = scan_port(ip, port, timeout=timeout, grab_banners=grab_banners)
        with lock:
            scanned += 1
            if result:
                open_ports.append(result)
                print_open_port(result)
            # Progress bar every 500 ports
            if scanned % 500 == 0 or scanned == len(ports):
                pct = int((scanned / len(ports)) * 30)
                bar = f"[{'█' * pct}{'░' * (30 - pct)}]"
                print(f"\r  {c('dim', bar)} {scanned}/{len(ports)} scanned", end='', flush=True)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_and_collect, p) for p in ports]
        for _ in as_completed(futures):
            pass

    end_time = datetime.now()
    elapsed  = (end_time - start_time).total_seconds()

    print(f"\r  {' ' * 60}\r", end='')  # Clear progress line
    print(c('dim', '  ' + '─' * 80))

    # ── Summary ──────────────────────────────────────
    print()
    print(f"  {c('bold', '📊 SCAN SUMMARY')}")
    print(f"  {'─' * 40}")
    print(f"  Total ports scanned  : {c('white', str(len(ports)))}")
    print(f"  Open ports found     : {c('green' if open_ports else 'dim', str(len(open_ports)))}")
    print(f"  Scan duration        : {c('yellow', f'{elapsed:.2f}s')}")
    print(f"  Scan rate            : {c('cyan', f'{len(ports)/elapsed:.0f} ports/sec')}")

    if open_ports:
        print()
        print(f"  {c('bold', '🔍 RISK BREAKDOWN')}")
        risk_counts = {}
        for r in open_ports:
            lvl = r["risk"]
            risk_counts[lvl] = risk_counts.get(lvl, 0) + 1
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if level in risk_counts:
                rc = risk_color(level)
                icon = risk_icon(level)
                print(f"  {icon} {c(rc, level.ljust(10))} : {risk_counts[level]} port(s)")

        print()
        print(f"  {c('bold', '💡 SECURITY RECOMMENDATIONS')}")
        seen_notes = set()
        for r in sorted(open_ports, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["risk"])):
            if r["risk"] in ("CRITICAL", "HIGH") and r["note"] not in seen_notes:
                seen_notes.add(r["note"])
                print(f"  {risk_icon(r['risk'])} {c('bold', r['service'])}: {c('dim', r['note'])}")

    # ── JSON output ───────────────────────────────────
    if output_file:
        report = {
            "scan_info": {
                "target": target,
                "ip": ip,
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_seconds": round(elapsed, 2),
                "ports_scanned": len(ports),
                "threads": threads,
                "timeout": timeout,
            },
            "open_ports": open_ports,
            "summary": {
                "total_open": len(open_ports),
                "risk_breakdown": risk_counts if open_ports else {},
            }
        }
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print()
        print(f"  {c('green', '✔')} Report saved to {c('cyan', output_file)}")

    print()
    print(c('dim', '  ⚠  Remember: Only scan systems you own or have written permission to scan.'))
    print()

def main():
    parser = argparse.ArgumentParser(
        description="CyberScan — Educational Port Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  %(prog)s localhost
  %(prog)s 192.168.1.1 -p 1-1024
  %(prog)s example.com -p 80,443,8080,8443 --banners
  %(prog)s 10.0.0.1 -p 1-65535 -t 200 --timeout 0.5
  %(prog)s scanme.nmap.org --preset common -o report.json

⚠  LEGAL NOTICE: Only scan systems you own or have explicit written permission to scan.
"""
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports",
                        default=None,
                        help="Port range: '1-1024', '80,443', or '22-25,80,443' (default: top 1000)")
    parser.add_argument("--preset",
                        choices=["quick", "common", "web", "db", "full"],
                        default=None,
                        help=("Port presets:\n"
                              "  quick  — Top 20 ports\n"
                              "  common — Top 200 ports\n"
                              "  web    — HTTP/HTTPS variants\n"
                              "  db     — Database ports\n"
                              "  full   — All 65535 ports"))
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--banners", action="store_true",
                        help="Attempt to grab service banners (slower)")
    parser.add_argument("-o", "--output",
                        help="Save results to JSON file")

    args = parser.parse_args()

    # Preset port lists
    presets = {
        "quick":  [21,22,23,25,53,80,110,139,143,443,445,3306,3389,5900,8080],
        "common": list(COMMON_SERVICES.keys()),
        "web":    [80,81,443,591,593,832,981,1010,1311,2082,2087,2095,2096,
                   4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,
                   7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,
                   8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,
                   8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,
                   12443,16080,18091,18092,20720,28017],
        "db":     [1433,1434,1521,2483,2484,3306,3351,5432,5984,6379,7000,7001,
                   7199,8086,8087,8088,8098,9042,9160,9200,9300,11211,27017,27018,27019,
                   28015,28017,50000,50070,50075],
        "full":   list(range(1, 65536)),
    }

    if args.preset:
        ports = presets[args.preset]
    elif args.ports:
        ports = parse_port_range(args.ports)
    else:
        # Default: top ~1000 well-known ports
        ports = list(range(1, 1025))

    run_scan(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        grab_banners=args.banners,
        output_file=args.output,
    )

if __name__ == "__main__":
    main()
