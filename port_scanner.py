#!/usr/bin/env python3
"""
Port Scanning Module - Part of the WiFi Analyzer Tool
This module provides functionality to scan for open ports and services on network devices.
"""

import os
import sys
import time
import argparse
import subprocess
from datetime import datetime
import socket
import json
import threading
import signal
import nmap
import ipaddress
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self):
        self.targets = []
        self.results = {}
        self.interface = None
        self.save_location = None
        self.scan_active = False
        self.nm = nmap.PortScanner()
        self.common_ports = {
            'tcp': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
            'udp': [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1701, 1900, 4500, 5353]
        }
        self.vulnerability_checks = {
            21: self.check_ftp_anonymous,
            22: self.check_ssh_version,
            23: self.check_telnet_banner,
            25: self.check_smtp_open_relay,
            80: self.check_http_headers,
            443: self.check_ssl_version,
            445: self.check_smb_version,
            3306: self.check_mysql_version,
            3389: self.check_rdp_security
        }
    
    def check_root(self):
        """Check if the script is running with root privileges."""
        if os.geteuid() != 0:
            print("Error: This script must be run as root.")
            print("Please run with sudo or as root user.")
            sys.exit(1)
    
    def add_target(self, target):
        """Add a target to scan."""
        try:
            # Check if target is a valid IP address or network
            ipaddress.ip_network(target, strict=False)
            self.targets.append(target)
            print(f"Added target: {target}")
        except ValueError:
            try:
                # Try to resolve hostname
                ip = socket.gethostbyname(target)
                self.targets.append(ip)
                print(f"Added target: {target} ({ip})")
            except socket.gaierror:
                print(f"Error: Invalid target '{target}'. Must be a valid IP, network, or hostname.")
    
    def add_targets_from_file(self, filename):
        """Add targets from a file, one per line."""
        if not os.path.exists(filename):
            print(f"Error: File {filename} not found.")
            return
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    target = line.strip()
                    if target and not target.startswith('#'):
                        self.add_target(target)
        except Exception as e:
            print(f"Error reading targets from file: {e}")
    
    def scan_port(self, target, port, protocol='tcp', timeout=1):
        """Scan a single port on a target."""
        try:
            if protocol == 'tcp':
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:  # UDP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            s.settimeout(timeout)
            
            if protocol == 'tcp':
                result = s.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port, protocol)
                    except:
                        service = "unknown"
                    return port, True, service
            else:  # UDP is trickier, we'll send a packet and see if we get an ICMP unreachable
                s.sendto(b'', (target, port))
                try:
                    s.recvfrom(1024)
                    try:
                        service = socket.getservbyport(port, protocol)
                    except:
                        service = "unknown"
                    return port, True, service
                except socket.timeout:
                    # No ICMP response, port might be open or filtered
                    try:
                        service = socket.getservbyport(port, protocol)
                    except:
                        service = "unknown"
                    return port, True, service  # Assume open for UDP
        except Exception as e:
            pass
        finally:
            s.close()
        
        return port, False, None
    
    def quick_scan(self, target, ports=None, protocol='tcp'):
        """Perform a quick scan of common ports on a target."""
        if ports is None:
            ports = self.common_ports[protocol]
        
        open_ports = []
        
        print(f"Quick scanning {target} for {len(ports)} {protocol.upper()} ports...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.scan_port, target, port, protocol) for port in ports]
            for future in futures:
                port, is_open, service = future.result()
                if is_open:
                    open_ports.append((port, service))
                    print(f"  {protocol.upper()} port {port} ({service}): Open")
        
        return open_ports
    
    def nmap_scan(self, target, ports=None, scan_type='-sS', arguments=None):
        """Perform a more comprehensive scan using nmap."""
        if not self.scan_active:
            return {}
        
        if ports:
            port_range = ','.join(map(str, ports))
        else:
            port_range = '1-1024'
        
        args = f"{scan_type} -Pn -T4"
        if arguments:
            args += f" {arguments}"
        
        print(f"Starting nmap scan of {target} (ports: {port_range})...")
        print(f"Scan arguments: {args}")
        
        try:
            self.nm.scan(hosts=target, ports=port_range, arguments=args)
            
            scan_results = {}
            
            for host in self.nm.all_hosts():
                scan_results[host] = {}
                
                # Get host information
                if 'hostnames' in self.nm[host]:
                    scan_results[host]['hostnames'] = self.nm[host]['hostnames']
                
                # Get OS detection results if available
                if 'osmatch' in self.nm[host]:
                    scan_results[host]['os'] = self.nm[host]['osmatch']
                
                # Get port information
                scan_results[host]['ports'] = {}
                
                for proto in self.nm[host].all_protocols():
                    scan_results[host]['ports'][proto] = []
                    
                    for port in self.nm[host][proto]:
                        port_info = self.nm[host][proto][port]
                        port_data = {
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        
                        scan_results[host]['ports'][proto].append(port_data)
                        
                        # Print port information
                        service_detail = f"{port_data['service']}"
                        if port_data['product']:
                            service_detail += f" ({port_data['product']}"
                            if port_data['version']:
                                service_detail += f" {port_data['version']}"
                            service_detail += ")"
                        
                        print(f"  {proto.upper()} port {port} ({service_detail}): {port_data['state']}")
            
            return scan_results
            
        except Exception as e:
            print(f"Error during nmap scan: {e}")
            return {}
    
    def check_vulnerabilities(self, target, open_ports, protocol='tcp'):
        """Check for common vulnerabilities on open ports."""
        vulnerabilities = []
        
        print(f"\nChecking for vulnerabilities on {target}...")
        
        for port, service in open_ports:
            if port in self.vulnerability_checks:
                try:
                    vuln_check = self.vulnerability_checks[port]
                    result = vuln_check(target, port)
                    if result:
                        vulnerabilities.append({
                            'port': port,
                            'service': service,
                            'vulnerability': result
                        })
                        print(f"  Vulnerability found on port {port} ({service}): {result}")
                except Exception as e:
                    print(f"  Error checking vulnerabilities on port {port}: {e}")
        
        return vulnerabilities
    
    # Vulnerability check methods
    def check_ftp_anonymous(self, target, port):
        """Check if FTP allows anonymous login."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                banner = s.recv(1024).decode(errors='ignore')
                
                # Send anonymous login
                s.send(b'USER anonymous\r\n')
                response = s.recv(1024).decode(errors='ignore')
                
                s.send(b'PASS anonymous@example.com\r\n')
                response = s.recv(1024).decode(errors='ignore')
                
                if '230' in response:  # 230 = Login successful
                    return "Anonymous FTP login allowed"
        except:
            pass
        return None
    
    def check_ssh_version(self, target, port):
        """Check for outdated SSH version."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                banner = s.recv(1024).decode(errors='ignore')
                
                if 'SSH-1.' in banner:
                    return "Outdated SSH protocol version 1 detected"
                elif 'SSH-2.0-OpenSSH_4.' in banner or 'SSH-2.0-OpenSSH_5.' in banner:
                    return f"Outdated OpenSSH version detected: {banner.strip()}"
        except:
            pass
        return None
    
    def check_telnet_banner(self, target, port):
        """Check telnet banner for information disclosure."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                banner = s.recv(1024).decode(errors='ignore')
                
                if banner and len(banner) > 0:
                    if any(os in banner.lower() for os in ['linux', 'unix', 'windows', 'cisco', 'router']):
                        return f"Telnet banner reveals system information: {banner.strip()}"
                
                return "Telnet service enabled (security risk)"
        except:
            pass
        return None
    
    def check_smtp_open_relay(self, target, port):
        """Check if SMTP server might be an open relay."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                banner = s.recv(1024).decode(errors='ignore')
                
                # Try EHLO command
                s.send(b'EHLO test.com\r\n')
                response = s.recv(1024).decode(errors='ignore')
                
                # Check for authentication requirement
                if '250' in response and 'AUTH' not in response:
                    return "SMTP server might be an open relay (no authentication required)"
        except:
            pass
        return None
    
    def check_http_headers(self, target, port):
        """Check HTTP headers for security issues."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                
                request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                s.send(request.encode())
                
                response = b""
                while True:
                    try:
                        data = s.recv(4096)
                        if not data:
                            break
                        response += data
                    except:
                        break
                
                headers = response.decode(errors='ignore').split('\r\n\r\n')[0]
                
                issues = []
                
                # Check for server header
                if 'Server:' in headers:
                    server_line = [line for line in headers.split('\r\n') if line.startswith('Server:')][0]
                    server = server_line.split(':', 1)[1].strip()
                    if any(v in server.lower() for v in ['apache/1.', 'apache/2.0', 'apache/2.2', 'microsoft-iis/5.', 'microsoft-iis/6.']):
                        issues.append(f"Outdated web server: {server}")
                
                # Check for missing security headers
                if 'X-Frame-Options:' not in headers:
                    issues.append("Missing X-Frame-Options header (clickjacking risk)")
                
                if 'X-XSS-Protection:' not in headers:
                    issues.append("Missing X-XSS-Protection header")
                
                if 'Content-Security-Policy:' not in headers:
                    issues.append("Missing Content-Security-Policy header")
                
                if issues:
                    return "; ".join(issues)
        except:
            pass
        return None
    
    def check_ssl_version(self, target, port):
        """Check for outdated SSL/TLS versions."""
        try:
            # Use nmap for SSL version detection
            result = self.nm.scan(target, str(port), arguments='-sV --script ssl-enum-ciphers')
            
            if target in result['scan'] and 'tcp' in result['scan'][target] and port in result['scan'][target]['tcp']:
                script_output = result['scan'][target]['tcp'][port].get('script', {}).get('ssl-enum-ciphers', '')
                
                if 'SSLv2' in script_output or 'SSLv3' in script_output:
                    return "Outdated SSL version (SSLv2/SSLv3) supported"
                elif 'TLSv1.0' in script_output:
                    return "Outdated TLS version (TLSv1.0) supported"
        except:
            pass
        return None
    
    def check_smb_version(self, target, port):
        """Check for outdated SMB version."""
        try:
            # Use nmap for SMB version detection
            result = self.nm.scan(target, str(port), arguments='-sV --script smb-protocols')
            
            if target in result['scan'] and 'tcp' in result['scan'][target] and port in result['scan'][target]['tcp']:
                script_output = result['scan'][target]['tcp'][port].get('script', {}).get('smb-protocols', '')
                
                if 'SMBv1' in script_output:
                    return "Outdated SMB version (SMBv1) supported (WannaCry vulnerability)"
        except:
            pass
        return None
    
    def check_mysql_version(self, target, port):
        """Check for outdated MySQL version."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((target, port))
                banner = s.recv(1024)
                
                if banner:
                    version_info = banner[5:].decode(errors='ignore').split('\0')[0]
                    if version_info.startswith('5.0') or version_info.startswith('4.'):
                        return f"Outdated MySQL version: {version_info}"
        except:
            pass
        return None
    
    def check_rdp_security(self, target, port):
        """Check for RDP security issues."""
        try:
            # Use nmap for RDP security check
            result = self.nm.scan(target, str(port), arguments='-sV --script rdp-vuln-ms12-020')
            
            if target in result['scan'] and 'tcp' in result['scan'][target] and port in result['scan'][target]['tcp']:
                script_output = result['scan'][target]['tcp'][port].get('script', {}).get('rdp-vuln-ms12-020', '')
                
                if 'VULNERABLE' in script_output:
                    return "RDP MS12-020 vulnerability detected"
        except:
            pass
        return None
    
    def scan_target(self, target, scan_type='quick', ports=None, protocol='tcp', check_vulns=True):
        """Scan a single target for open ports and services."""
        if not self.scan_active:
            return
        
        print(f"\n{'='*80}")
        print(f"Scanning target: {target}")
        print(f"{'='*80}")
        
        self.results[target] = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_type': scan_type,
            'open_ports': {},
            'vulnerabilities': []
        }
        
        if scan_type == 'quick':
            # Perform quick TCP scan
            tcp_open_ports = self.quick_scan(target, ports, 'tcp')
            if tcp_open_ports:
                self.results[target]['open_ports']['tcp'] = tcp_open_ports
            
            # Perform quick UDP scan if requested
            if protocol == 'both' or protocol == 'udp':
                udp_open_ports = self.quick_scan(target, ports, 'udp')
                if udp_open_ports:
                    self.results[target]['open_ports']['udp'] = udp_open_ports
            
            # Check for vulnerabilities
            if check_vulns and 'tcp' in self.results[target]['open_ports']:
                vulns = self.check_vulnerabilities(target, self.results[target]['open_ports']['tcp'])
                if vulns:
                    self.results[target]['vulnerabilities'] = vulns
        
        elif scan_type == 'nmap':
            # Perform nmap scan
            if protocol == 'tcp' or protocol == 'both':
                tcp_args = '-sV -O --script=banner,version'
                tcp_results = self.nmap_scan(target, ports, '-sS', tcp_args)
                if tcp_results:
                    self.results[target]['nmap_results'] = tcp_results
            
            if protocol == 'udp' or protocol == 'both':
                udp_args = '-sV --script=banner,version'
                udp_results = self.nmap_scan(target, ports, '-sU', udp_args)
                if udp_results and target in udp_results:
                    if 'nmap_results' not in self.results[target]:
                        self.results[target]['nmap_results'] = {}
                    
                    # Merge UDP results with existing results
                    for host in udp_results:
                        if host not in self.results[target]['nmap_results']:
                            self.results[target]['nmap_results'][host] = udp_results[host]
                        else:
                            if 'ports' in udp_results[host] and 'udp' in udp_results[host]['ports']:
                                if 'ports' not in self.results[target]['nmap_results'][host]:
                                    self.results[target]['nmap_results'][host]['ports'] = {}
                                
                                self.results[target]['nmap_results'][host]['ports']['udp'] = udp_results[host]['ports']['udp']
        
        print(f"Scan of {target} complete.")
    
    def start_scan(self, scan_type='quick', ports=None, protocol='tcp', check_vulns=True):
        """Start scanning all targets."""
        if not self.targets:
            print("Error: No targets specified.")
            return
        
        print(f"\nStarting port scan of {len(self.targets)} targets...")
        print(f"Scan type: {scan_type}")
        print(f"Protocol: {protocol}")
        if ports:
            print(f"Ports: {', '.join(map(str, ports))}")
        else:
            print("Ports: Default")
        print(f"Vulnerability checks: {'Enabled' if check_vulns else 'Disabled'}")
        
        self.scan_active = True
        start_time = time.time()
        
        try:
            for target in self.targets:
                if not self.scan_active:
                    break
                self.scan_target(target, scan_type, ports, protocol, check_vulns)
            
            scan_duration = time.time() - start_time
            print(f"\nScan completed in {scan_duration:.2f} seconds.")
            print(f"Scanned {len(self.targets)} targets, found open ports on {sum(1 for t in self.results if self.results[t]['open_ports'])} targets.")
            
            if check_vulns:
                vuln_count = sum(len(self.results[t]['vulnerabilities']) for t in self.results if 'vulnerabilities' in self.results[t])
                print(f"Detected {vuln_count} potential vulnerabilities.")
        
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            self.scan_active = False
        except Exception as e:
            print(f"\nError during scan: {e}")
            self.scan_active = False
    
    def save_results(self, filename=None):
        """Save scan results to a file."""
        if not self.results:
            print("No scan results to save.")
            return
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"port_scan_{timestamp}.json"
        
        if self.save_location:
            filename = os.path.join(self.save_location, filename)
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"Scan results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='Network Port Scanner')
    parser.add_argument('-t', '--target', help='Target IP, hostname, or network (CIDR notation)')
    parser.add_argument('-f', '--file', help='File containing targets, one per line')
    parser.add_argument('-p', '--ports', help='Ports to scan (comma-separated, e.g., 22,80,443)')
    parser.add_argument('-T', '--type', choices=['quick', 'nmap'], default='quick', help='Scan type')
    parser.add_argument('-P', '--protocol', choices=['tcp', 'udp', 'both'], default='tcp', help='Protocol to scan')
    parser.add_argument('-v', '--vulns', action='store_true', help='Check for vulnerabilities')
    parser.add_argument('-s', '--save', action='store_true', help='Save results to file')
    parser.add_argument('-o', '--output', help='Output directory for results')
    
    args = parser.parse_args()
    
    scanner = PortScanner()
    scanner.check_root()
    
    if args.output:
        scanner.save_location = args.output
    
    # Add targets
    if args.target:
        scanner.add_target(args.target)
    
    if args.file:
        scanner.add_targets_from_file(args.file)
    
    if not scanner.targets:
        parser.print_help()
        sys.exit(1)
    
    # Parse ports
    ports = None
    if args.ports:
        try:
            ports = [int(p) for p in args.ports.split(',')]
        except ValueError:
            print("Error: Invalid port specification. Must be comma-separated integers.")
            sys.exit(1)
    
    try:
        scanner.start_scan(args.type, ports, args.protocol, args.vulns)
        
        if args.save:
            scanner.save_results()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user.")

if __name__ == "__main__":
    main()
