#!/usr/bin/env python3
"""
ReconMaster - Comprehensive Reconnaissance Tool
Performs subdomain enumeration, port scanning, HTTP header analysis,
and basic defensive security checks.
"""

import argparse
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import requests


class ReconMaster:
    def __init__(self, target, ports=None, threads=10, timeout=1.0, output_file=None):
        self.target = target.strip().rstrip('.')
        self.ports = ports or list(range(1, 1025))
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.lock = Lock()
        self.results = {
            'subdomains': [],
            'open_ports': [],
            'headers': {},
            'vulnerabilities': [],
            'target_ip': '',
        }

    def _is_ip_target(self):
        try:
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            return False

    def _resolve_target_ip(self):
        try:
            self.results['target_ip'] = socket.gethostbyname(self.target)
        except socket.gaierror:
            self.results['target_ip'] = 'unresolved'

    def enumerate_subdomains(self):
        """Enumerate common subdomains for domain targets only."""
        print("[+] Enumerating subdomains...")

        if self._is_ip_target():
            print("[-] Target is an IP address, skipping subdomain enumeration")
            return

        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api',
            'dev', 'test', 'staging', 'blog', 'shop',
        ]
        found_subs = []

        def check_sub(sub):
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                with self.lock:
                    found_subs.append(f"{fqdn} ({ip})")
            except socket.gaierror:
                return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_sub, sub) for sub in common_subs]
            for _ in as_completed(futures):
                pass

        self.results['subdomains'] = sorted(found_subs)
        print(f"[+] Found {len(found_subs)} subdomains")

    def scan_ports(self):
        """Scan requested TCP ports using a thread pool."""
        print("[+] Scanning ports...")
        open_ports = []

        def scan_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((self.target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = 'unknown'
                    with self.lock:
                        open_ports.append({'port': port, 'service': service})
            except OSError:
                return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_port, port) for port in self.ports]
            for _ in as_completed(futures):
                pass

        self.results['open_ports'] = sorted(open_ports, key=lambda item: item['port'])
        print(f"[+] Found {len(open_ports)} open ports")

    def check_headers(self):
        """Check HTTP response headers for baseline security hardening."""
        print("[+] Checking HTTP headers...")
        session = requests.Session()
        targets = [f"https://{self.target}", f"http://{self.target}"]

        for url in targets:
            try:
                response = session.get(
                    url,
                    timeout=max(2, self.timeout * 3),
                    allow_redirects=True,
                )
                headers = dict(response.headers)
                self.results['headers'] = {
                    'requested_url': url,
                    'final_url': response.url,
                    'status_code': response.status_code,
                    'headers': headers,
                }

                required_headers = [
                    'Content-Security-Policy',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Strict-Transport-Security',
                    'Referrer-Policy',
                ]
                missing = [name for name in required_headers if name not in headers]
                if missing:
                    self.results['vulnerabilities'].append({
                        'type': 'Missing Security Headers',
                        'details': f"Missing: {', '.join(missing)}",
                        'severity': 'Medium',
                    })

                print(f"[+] Headers checked via {url}")
                return
            except requests.RequestException:
                continue

        print("[-] Header check failed over both HTTPS and HTTP")

    def check_vulnerabilities(self):
        """Run basic non-intrusive risk checks based on observed findings."""
        print("[+] Checking for basic vulnerabilities...")

        dangerous_ports = [21, 23, 25, 53, 110, 143, 993, 995]
        for port_info in self.results['open_ports']:
            if port_info['port'] in dangerous_ports:
                self.results['vulnerabilities'].append({
                    'type': 'Potentially Sensitive Service Exposed',
                    'details': f"Port {port_info['port']} ({port_info['service']}) is open",
                    'severity': 'Medium',
                })

        for port_info in self.results['open_ports']:
            service_name = str(port_info['service']).lower()
            if port_info['port'] not in [80, 443] and 'http' in service_name:
                self.results['vulnerabilities'].append({
                    'type': 'HTTP on Non-Standard Port',
                    'details': f"HTTP service detected on port {port_info['port']}",
                    'severity': 'Low',
                })

        print(f"[+] Found {len(self.results['vulnerabilities'])} potential issues")

    def run(self):
        """Run all reconnaissance tasks."""
        start_time = time.time()

        self._resolve_target_ip()
        self.enumerate_subdomains()
        self.scan_ports()
        self.check_headers()
        self.check_vulnerabilities()

        elapsed = time.time() - start_time
        self.results['scan_time'] = f"{elapsed:.2f} seconds"

        self.save_results()
        self.print_summary()

    def save_results(self):
        """Save results to JSON file."""
        if self.output_file:
            with open(self.output_file, 'w', encoding='utf-8') as file_handle:
                json.dump(self.results, file_handle, indent=2)
            print(f"[+] Results saved to {self.output_file}")

    def print_summary(self):
        """Print a summary of findings."""
        print("\n" + "=" * 50)
        print("RECON MASTER - RECONNAISSANCE SUMMARY")
        print("=" * 50)
        print(f"Target: {self.target}")
        print(f"Target IP: {self.results.get('target_ip', 'unknown')}")
        print(f"Scan Time: {self.results['scan_time']}")
        print(f"Subdomains Found: {len(self.results['subdomains'])}")
        print(f"Open Ports: {len(self.results['open_ports'])}")
        print(f"Potential Issues: {len(self.results['vulnerabilities'])}")

        print("\nSubdomains:")
        for subdomain in self.results['subdomains']:
            print(f"  - {subdomain}")

        print("\nOpen Ports:")
        for port in self.results['open_ports']:
            print(f"  - {port['port']}/{port['service']}")

        print("\nPotential Issues:")
        for vulnerability in self.results['vulnerabilities']:
            print(f"  - [{vulnerability['severity']}] {vulnerability['type']}: {vulnerability['details']}")

        print("=" * 50)


def parse_ports(port_value):
    if '-' in port_value:
        start, end = map(int, port_value.split('-', maxsplit=1))
        if start < 1 or end > 65535 or start > end:
            raise ValueError("Port range must be valid and between 1-65535")
        return list(range(start, end + 1))

    single_port = int(port_value)
    if single_port < 1 or single_port > 65535:
        raise ValueError("Port must be between 1-65535")
    return [single_port]


def main():
    parser = argparse.ArgumentParser(description="ReconMaster - Comprehensive Recon Tool")
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-1000) or single port", default="1-1024")
    parser.add_argument("-t", "--threads", type=int, help="Number of threads", default=10)
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--timeout", type=float, help="Socket timeout", default=1.0)

    args = parser.parse_args()

    if args.threads < 1:
        parser.error("--threads must be at least 1")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    recon = ReconMaster(
        args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        output_file=args.output,
    )
    recon.run()


if __name__ == "__main__":
    main()
