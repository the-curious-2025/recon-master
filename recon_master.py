#!/usr/bin/env python3
"""
ReconMaster - Comprehensive Reconnaissance Tool for Penetration Testers
Performs subdomain enumeration, port scanning, HTTP header analysis, and basic vulnerability checks.
Author: the-curious
License: MIT
"""

import argparse
import socket
import threading
import requests
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class ReconMaster:
    def __init__(self, target, ports=None, threads=10, timeout=1.0, output_file=None):
        self.target = target.rstrip('.')
        self.ports = ports or list(range(1, 1025))  # Default: 1-1024
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.results = {
            'subdomains': [],
            'open_ports': [],
            'headers': {},
            'vulnerabilities': []
        }

    def enumerate_subdomains(self):
        """Enumerate subdomains using common wordlist (basic implementation)"""
        print("[+] Enumerating subdomains...")
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog', 'shop']
        found_subs = []

        def check_sub(sub):
            try:
                ip = socket.gethostbyname(f"{sub}.{self.target}")
                found_subs.append(f"{sub}.{self.target} ({ip})")
            except socket.gaierror:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_sub, sub) for sub in common_subs]
            for future in as_completed(futures):
                pass  # Just wait

        self.results['subdomains'] = found_subs
        print(f"[+] Found {len(found_subs)} subdomains")

    def scan_ports(self):
        """Multithreaded port scanning"""
        print("[+] Scanning ports...")
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    open_ports.append({'port': port, 'service': service})
                sock.close()
            except:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_port, port) for port in self.ports]
            for future in as_completed(futures):
                pass

        self.results['open_ports'] = open_ports
        print(f"[+] Found {len(open_ports)} open ports")

    def check_headers(self):
        """Check HTTP headers for security issues"""
        print("[+] Checking HTTP headers...")
        try:
            url = f"http://{self.target}"
            response = requests.get(url, timeout=5)
            headers = dict(response.headers)
            self.results['headers'] = headers

            # Check for missing security headers
            security_headers = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security']
            missing = [h for h in security_headers if h not in headers]
            if missing:
                self.results['vulnerabilities'].append({
                    'type': 'Missing Security Headers',
                    'details': f"Missing: {', '.join(missing)}",
                    'severity': 'Medium'
                })

            print("[+] Headers checked")
        except requests.RequestException as e:
            print(f"[-] Header check failed: {e}")

    def check_vulnerabilities(self):
        """Basic vulnerability checks based on open ports and headers"""
        print("[+] Checking for basic vulnerabilities...")

        # Check for dangerous open ports
        dangerous_ports = [21, 23, 25, 53, 110, 143, 993, 995]  # FTP, Telnet, SMTP, etc.
        for port_info in self.results['open_ports']:
            if port_info['port'] in dangerous_ports:
                self.results['vulnerabilities'].append({
                    'type': 'Potentially Dangerous Port Open',
                    'details': f"Port {port_info['port']} ({port_info['service']}) is open and may be vulnerable",
                    'severity': 'High'
                })

        # Check for HTTP on non-standard ports
        for port_info in self.results['open_ports']:
            if port_info['port'] not in [80, 443] and 'http' in port_info['service'].lower():
                self.results['vulnerabilities'].append({
                    'type': 'HTTP on Non-Standard Port',
                    'details': f"HTTP service detected on port {port_info['port']}",
                    'severity': 'Low'
                })

        print(f"[+] Found {len(self.results['vulnerabilities'])} potential issues")

    def run(self):
        """Run all reconnaissance tasks"""
        start_time = time.time()

        self.enumerate_subdomains()
        self.scan_ports()
        self.check_headers()
        self.check_vulnerabilities()

        end_time = time.time()
        self.results['scan_time'] = f"{end_time - start_time:.2f} seconds"

        self.save_results()
        self.print_summary()

    def save_results(self):
        """Save results to JSON file"""
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"[+] Results saved to {self.output_file}")

    def print_summary(self):
        """Print a summary of findings"""
        print("\n" + "="*50)
        print("RECON MASTER - RECONNAISSANCE SUMMARY")
        print("="*50)
        print(f"Target: {self.target}")
        print(f"Scan Time: {self.results['scan_time']}")
        print(f"Subdomains Found: {len(self.results['subdomains'])}")
        print(f"Open Ports: {len(self.results['open_ports'])}")
        print(f"Vulnerabilities: {len(self.results['vulnerabilities'])}")
        print("\nSubdomains:")
        for sub in self.results['subdomains']:
            print(f"  - {sub}")
        print("\nOpen Ports:")
        for port in self.results['open_ports']:
            print(f"  - {port['port']}/{port['service']}")
        print("\nVulnerabilities:")
        for vuln in self.results['vulnerabilities']:
            print(f"  - [{vuln['severity']}] {vuln['type']}: {vuln['details']}")
        print("="*50)

def main():
    parser = argparse.ArgumentParser(description="ReconMaster - Comprehensive Recon Tool")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000)", default="1-1024")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads", default=10)
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--timeout", type=float, help="Socket timeout", default=1.0)

    args = parser.parse_args()

    # Parse port range
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports = list(range(start, end + 1))
    else:
        ports = [int(args.ports)]

    recon = ReconMaster(args.target, ports=ports, threads=args.threads, timeout=args.timeout, output_file=args.output)
    recon.run()

if __name__ == "__main__":
    main()