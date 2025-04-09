#!/usr/bin/env python3
"""
Traffic Analysis Module - Part of the WiFi Analyzer Tool
This module provides functionality to capture and analyze network traffic.
"""

import os
import sys
import time
import argparse
import subprocess
from datetime import datetime
import scapy.all as scapy
from scapy.layers import http
import pyshark
import json
import threading
import signal
import re
import psutil
from collections import defaultdict, Counter

class TrafficAnalyzer:
    def __init__(self):
        self.interface = None
        self.capture_file = None
        self.save_location = None
        self.packet_count = 0
        self.http_requests = []
        self.connections = defaultdict(list)
        self.protocols = Counter()
        self.hosts = Counter()
        self.data_usage = defaultdict(int)
        self.capture_active = False
        self.capture_thread = None
        self.live_display = False
    
    def check_root(self):
        """Check if the script is running with root privileges."""
        if os.geteuid() != 0:
            print("Error: This script must be run as root.")
            print("Please run with sudo or as root user.")
            sys.exit(1)
    
    def get_interfaces(self):
        """Get all network interfaces."""
        return scapy.get_if_list()
    
    def set_interface(self, interface=None):
        """Set the network interface to use."""
        available_interfaces = self.get_interfaces()
        
        if not available_interfaces:
            print("Error: No network interfaces found.")
            sys.exit(1)
        
        if interface is None:
            # If no interface specified, try to find a suitable one
            for iface in available_interfaces:
                # Skip loopback
                if iface == "lo":
                    continue
                
                # Use the first non-loopback interface
                self.interface = iface
                print(f"Using network interface: {self.interface}")
                return
        elif interface in available_interfaces:
            self.interface = interface
            print(f"Using network interface: {self.interface}")
        else:
            print(f"Error: Interface {interface} not found.")
            print(f"Available interfaces: {', '.join(available_interfaces)}")
            sys.exit(1)
    
    def packet_callback(self, packet):
        """Process captured packets for analysis."""
        self.packet_count += 1
        
        # Extract source and destination
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            length = len(packet)
            
            # Update data usage statistics
            self.data_usage[src_ip] += length
            
            # Update connection tracking
            connection = (src_ip, dst_ip, protocol)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.connections[connection].append(timestamp)
            
            # Update protocol statistics
            if protocol == 6:  # TCP
                self.protocols["TCP"] += 1
                if packet.haslayer(scapy.TCP):
                    dst_port = packet[scapy.TCP].dport
                    if dst_port == 80:
                        self.protocols["HTTP"] += 1
                    elif dst_port == 443:
                        self.protocols["HTTPS"] += 1
            elif protocol == 17:  # UDP
                self.protocols["UDP"] += 1
                if packet.haslayer(scapy.UDP):
                    dst_port = packet[scapy.UDP].dport
                    if dst_port == 53:
                        self.protocols["DNS"] += 1
            elif protocol == 1:  # ICMP
                self.protocols["ICMP"] += 1
            
            # Update host statistics
            self.hosts[dst_ip] += 1
            
            # Live display
            if self.live_display and self.packet_count % 10 == 0:
                self.print_live_stats()
        
        # HTTP traffic analysis
        if packet.haslayer(http.HTTPRequest):
            # Extract HTTP information
            http_layer = packet.getlayer(http.HTTPRequest)
            ip_layer = packet.getlayer(scapy.IP)
            
            # Get HTTP method and URL
            method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else "Unknown"
            host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else "Unknown"
            path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else "/"
            url = f"http://{host}{path}"
            
            # Record HTTP request
            request = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'method': method,
                'url': url
            }
            
            # Check for credentials in POST requests
            if method == "POST" and packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode(errors='ignore')
                if "username" in payload or "password" in payload or "user" in payload or "pass" in payload:
                    request['contains_credentials'] = True
                    request['payload'] = payload
            
            self.http_requests.append(request)
            
            # Print HTTP request information
            print(f"[HTTP] {request['timestamp']} - {request['src_ip']} -> {method} {url}")
    
    def print_live_stats(self):
        """Print live statistics during capture."""
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"Traffic Analysis - Live Statistics")
        print(f"Interface: {self.interface}")
        print(f"Packets captured: {self.packet_count}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\nTop Protocols:")
        for protocol, count in self.protocols.most_common(5):
            print(f"  {protocol}: {count}")
        print("\nTop Destinations:")
        for host, count in self.hosts.most_common(5):
            print(f"  {host}: {count}")
        print("\nTop Data Usage (bytes):")
        top_usage = sorted(self.data_usage.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, usage in top_usage:
            print(f"  {ip}: {usage}")
        print("\nRecent HTTP Requests:")
        for request in self.http_requests[-5:]:
            print(f"  {request['timestamp']} - {request['src_ip']} -> {request['method']} {request['url']}")
    
    def start_capture(self, duration=None, packet_filter=None, max_packets=None):
        """Start capturing and analyzing network traffic."""
        if self.interface is None:
            print("Error: No interface selected.")
            return
        
        # Create capture file if needed
        if self.capture_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.capture_file = f"traffic_capture_{timestamp}.pcap"
            if self.save_location:
                self.capture_file = os.path.join(self.save_location, self.capture_file)
        
        print(f"\nStarting traffic capture on {self.interface}")
        if duration:
            print(f"Capture will run for {duration} seconds")
        if packet_filter:
            print(f"Using filter: {packet_filter}")
        print(f"Saving capture to: {self.capture_file}")
        print("Press Ctrl+C to stop capture")
        
        # Reset counters
        self.packet_count = 0
        self.http_requests = []
        self.connections = defaultdict(list)
        self.protocols = Counter()
        self.hosts = Counter()
        self.data_usage = defaultdict(int)
        
        # Set capture active flag
        self.capture_active = True
        
        # Start capture in a separate thread
        def capture_thread_func():
            try:
                # Build filter string
                filter_str = packet_filter if packet_filter else ""
                
                # Start packet capture
                scapy.sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    filter=filter_str,
                    store=False,
                    timeout=duration,
                    count=max_packets
                )
                
                # Capture complete
                if self.capture_active:
                    print("\nCapture complete!")
                    self.capture_active = False
                    self.print_summary()
            except Exception as e:
                print(f"\nError during capture: {e}")
                self.capture_active = False
        
        self.capture_thread = threading.Thread(target=capture_thread_func)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        try:
            # Wait for capture to complete or user interruption
            while self.capture_active and self.capture_thread.is_alive():
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
            self.capture_active = False
            time.sleep(1)  # Give the thread time to clean up
            self.print_summary()
    
    def print_summary(self):
        """Print a summary of the captured traffic."""
        print("\n" + "="*80)
        print(f"Traffic Analysis Summary")
        print("="*80)
        print(f"Interface: {self.interface}")
        print(f"Capture duration: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total packets captured: {self.packet_count}")
        
        print("\nProtocol Distribution:")
        for protocol, count in self.protocols.most_common():
            percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
            print(f"  {protocol}: {count} packets ({percentage:.2f}%)")
        
        print("\nTop 10 Destinations:")
        for host, count in self.hosts.most_common(10):
            percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
            print(f"  {host}: {count} packets ({percentage:.2f}%)")
        
        print("\nTop 10 Data Usage:")
        top_usage = sorted(self.data_usage.items(), key=lambda x: x[1], reverse=True)[:10]
        total_bytes = sum(self.data_usage.values())
        for ip, usage in top_usage:
            percentage = (usage / total_bytes) * 100 if total_bytes > 0 else 0
            print(f"  {ip}: {usage} bytes ({percentage:.2f}%)")
        
        print("\nHTTP Traffic Summary:")
        print(f"  Total HTTP requests: {len(self.http_requests)}")
        
        # Count HTTP methods
        http_methods = Counter(request['method'] for request in self.http_requests)
        for method, count in http_methods.most_common():
            print(f"  {method} requests: {count}")
        
        # Check for potential credential submissions
        cred_requests = [req for req in self.http_requests if req.get('contains_credentials', False)]
        if cred_requests:
            print(f"\nPotential credential submissions detected: {len(cred_requests)}")
            for req in cred_requests:
                print(f"  {req['timestamp']} - {req['src_ip']} -> {req['url']}")
    
    def analyze_pcap(self, pcap_file):
        """Analyze an existing PCAP file."""
        if not os.path.exists(pcap_file):
            print(f"Error: PCAP file {pcap_file} not found.")
            return
        
        print(f"\nAnalyzing PCAP file: {pcap_file}")
        
        # Reset counters
        self.packet_count = 0
        self.http_requests = []
        self.connections = defaultdict(list)
        self.protocols = Counter()
        self.hosts = Counter()
        self.data_usage = defaultdict(int)
        
        try:
            # Use PyShark for more detailed analysis
            capture = pyshark.FileCapture(pcap_file)
            
            for packet in capture:
                self.packet_count += 1
                
                # Process IP layer
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.ip.proto
                    length = int(packet.length)
                    
                    # Update data usage statistics
                    self.data_usage[src_ip] += length
                    
                    # Update connection tracking
                    connection = (src_ip, dst_ip, protocol)
                    timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S')
                    self.connections[connection].append(timestamp)
                    
                    # Update protocol statistics
                    if hasattr(packet, 'tcp'):
                        self.protocols["TCP"] += 1
                        if hasattr(packet.tcp, 'dstport'):
                            dst_port = int(packet.tcp.dstport)
                            if dst_port == 80:
                                self.protocols["HTTP"] += 1
                            elif dst_port == 443:
                                self.protocols["HTTPS"] += 1
                    elif hasattr(packet, 'udp'):
                        self.protocols["UDP"] += 1
                        if hasattr(packet.udp, 'dstport'):
                            dst_port = int(packet.udp.dstport)
                            if dst_port == 53:
                                self.protocols["DNS"] += 1
                    elif hasattr(packet, 'icmp'):
                        self.protocols["ICMP"] += 1
                    
                    # Update host statistics
                    self.hosts[dst_ip] += 1
                
                # HTTP traffic analysis
                if hasattr(packet, 'http'):
                    # Extract HTTP information
                    if hasattr(packet.http, 'request_method'):
                        method = packet.http.request_method
                        host = packet.http.host if hasattr(packet.http, 'host') else "Unknown"
                        uri = packet.http.request_uri if hasattr(packet.http, 'request_uri') else "/"
                        url = f"http://{host}{uri}"
                        
                        # Record HTTP request
                        request = {
                            'timestamp': packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'src_ip': packet.ip.src,
                            'dst_ip': packet.ip.dst,
                            'method': method,
                            'url': url
                        }
                        
                        # Check for credentials in POST requests
                        if method == "POST" and hasattr(packet, 'data'):
                            payload = packet.data.data_data
                            if "username" in payload or "password" in payload or "user" in payload or "pass" in payload:
                                request['contains_credentials'] = True
                                request['payload'] = payload
                        
                        self.http_requests.append(request)
            
            # Print analysis summary
            self.print_summary()
            
        except Exception as e:
            print(f"Error analyzing PCAP file: {e}")
    
    def save_results(self, filename=None):
        """Save traffic analysis results to a file."""
        if self.packet_count == 0:
            print("No traffic data to save.")
            return
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"traffic_analysis_{timestamp}.json"
        
        if self.save_location:
            filename = os.path.join(self.save_location, filename)
        
        # Prepare results data
        results = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'interface': self.interface,
            'packet_count': self.packet_count,
            'protocols': dict(self.protocols),
            'top_hosts': dict(self.hosts.most_common(20)),
            'top_data_usage': {ip: usage for ip, usage in sorted(self.data_usage.items(), key=lambda x: x[1], reverse=True)[:20]},
            'http_requests': self.http_requests[:100]  # Limit to first 100 requests
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
            print(f"Traffic analysis results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('-d', '--duration', type=int, help='Capture duration in seconds')
    parser.add_argument('-f', '--filter', help='Packet filter expression (BPF syntax)')
    parser.add_argument('-c', '--count', type=int, help='Maximum number of packets to capture')
    parser.add_argument('-p', '--pcap', help='Analyze existing PCAP file instead of capturing')
    parser.add_argument('-l', '--live', action='store_true', help='Enable live statistics display')
    parser.add_argument('-s', '--save', action='store_true', help='Save analysis results to file')
    parser.add_argument('-o', '--output', help='Output directory for results')
    
    args = parser.parse_args()
    
    analyzer = TrafficAnalyzer()
    analyzer.check_root()
    
    if args.output:
        analyzer.save_location = args.output
    
    analyzer.live_display = args.live
    
    try:
        if args.pcap:
            analyzer.analyze_pcap(args.pcap)
        else:
            analyzer.set_interface(args.interface)
            analyzer.start_capture(args.duration, args.filter, args.count)
        
        if args.save:
            analyzer.save_results()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user.")

if __name__ == "__main__":
    main()
