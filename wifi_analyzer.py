#!/usr/bin/env python3
"""
WiFi Analyzer Tool - Main Integration Module
This module integrates all components of the WiFi Analyzer Tool into a unified interface.
"""

import os
import sys
import time
import argparse
import subprocess
from datetime import datetime
import threading
import signal
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from wifi_scanner import WiFiScanner
    from device_discovery import DeviceDiscovery
    from traffic_analyzer import TrafficAnalyzer
    from port_scanner import PortScanner
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all required modules are in the same directory.")
    sys.exit(1)

class WiFiAnalyzerCLI:
    """Command-line interface for the WiFi Analyzer Tool."""
    
    def __init__(self):
        self.wifi_scanner = WiFiScanner()
        self.device_discovery = DeviceDiscovery()
        self.traffic_analyzer = TrafficAnalyzer()
        self.port_scanner = PortScanner()
        self.results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
        
        # Create results directory if it doesn't exist
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
        
        # Set save locations for all modules
        self.wifi_scanner.save_location = self.results_dir
        self.device_discovery.save_location = self.results_dir
        self.traffic_analyzer.save_location = self.results_dir
        self.port_scanner.save_location = self.results_dir
    
    def check_root(self):
        """Check if the script is running with root privileges."""
        if os.geteuid() != 0:
            print("Error: This script must be run as root.")
            print("Please run with sudo or as root user.")
            sys.exit(1)
    
    def parse_arguments(self):
        """Parse command-line arguments."""
        parser = argparse.ArgumentParser(description='WiFi Analyzer Tool')
        subparsers = parser.add_subparsers(dest='command', help='Command to run')
        
        # WiFi Scanner command
        wifi_parser = subparsers.add_parser('wifi', help='Scan for WiFi networks')
        wifi_parser.add_argument('-i', '--interface', help='Wireless interface to use')
        wifi_parser.add_argument('-t', '--time', type=int, default=30, help='Scan duration in seconds')
        wifi_parser.add_argument('-n', '--no-hop', action='store_true', help='Disable channel hopping')
        wifi_parser.add_argument('-s', '--save', action='store_true', help='Save results to file')
        
        # Device Discovery command
        device_parser = subparsers.add_parser('devices', help='Discover devices on the network')
        device_parser.add_argument('-i', '--interface', help='Network interface to use')
        device_parser.add_argument('-t', '--target', help='Target network to scan (CIDR notation)')
        device_parser.add_argument('-m', '--monitor', action='store_true', help='Enable continuous monitoring')
        device_parser.add_argument('-d', '--duration', type=int, help='Monitoring duration in seconds')
        device_parser.add_argument('-n', '--interval', type=int, default=60, help='Monitoring interval in seconds')
        device_parser.add_argument('-s', '--save', action='store_true', help='Save results to file')
        
        # Traffic Analysis command
        traffic_parser = subparsers.add_parser('traffic', help='Analyze network traffic')
        traffic_parser.add_argument('-i', '--interface', help='Network interface to use')
        traffic_parser.add_argument('-d', '--duration', type=int, help='Capture duration in seconds')
        traffic_parser.add_argument('-f', '--filter', help='Packet filter expression (BPF syntax)')
        traffic_parser.add_argument('-c', '--count', type=int, help='Maximum number of packets to capture')
        traffic_parser.add_argument('-p', '--pcap', help='Analyze existing PCAP file instead of capturing')
        traffic_parser.add_argument('-l', '--live', action='store_true', help='Enable live statistics display')
        traffic_parser.add_argument('-s', '--save', action='store_true', help='Save analysis results to file')
        
        # Port Scanner command
        port_parser = subparsers.add_parser('ports', help='Scan for open ports and services')
        port_parser.add_argument('-t', '--target', help='Target IP, hostname, or network (CIDR notation)')
        port_parser.add_argument('-f', '--file', help='File containing targets, one per line')
        port_parser.add_argument('-p', '--ports', help='Ports to scan (comma-separated, e.g., 22,80,443)')
        port_parser.add_argument('-T', '--type', choices=['quick', 'nmap'], default='quick', help='Scan type')
        port_parser.add_argument('-P', '--protocol', choices=['tcp', 'udp', 'both'], default='tcp', help='Protocol to scan')
        port_parser.add_argument('-v', '--vulns', action='store_true', help='Check for vulnerabilities')
        port_parser.add_argument('-s', '--save', action='store_true', help='Save results to file')
        
        # GUI command
        gui_parser = subparsers.add_parser('gui', help='Launch graphical user interface')
        
        # All-in-one command
        all_parser = subparsers.add_parser('all', help='Run all scans in sequence')
        all_parser.add_argument('-i', '--interface', help='Network interface to use')
        all_parser.add_argument('-t', '--target', help='Target network to scan (CIDR notation)')
        all_parser.add_argument('-d', '--duration', type=int, default=30, help='Scan duration for each module in seconds')
        all_parser.add_argument('-s', '--save', action='store_true', help='Save all results to files')
        
        return parser.parse_args()
    
    def run_wifi_scan(self, args):
        """Run WiFi scanner module."""
        print("\n" + "="*80)
        print("WiFi Network Scanner")
        print("="*80)
        
        self.wifi_scanner.check_root()
        self.wifi_scanner.set_interface(args.interface)
        
        if args.no_hop:
            self.wifi_scanner.channel_hop = False
        
        try:
            self.wifi_scanner.start_scan(args.time)
            if args.save:
                self.wifi_scanner.save_results()
        except KeyboardInterrupt:
            print("\nWiFi scan interrupted by user.")
        finally:
            self.wifi_scanner.cleanup()
    
    def run_device_discovery(self, args):
        """Run device discovery module."""
        print("\n" + "="*80)
        print("Network Device Discovery")
        print("="*80)
        
        self.device_discovery.check_root()
        self.device_discovery.set_interface(args.interface)
        
        try:
            self.device_discovery.get_network_info()
            self.device_discovery.arp_scan(args.target)
            
            if args.monitor:
                self.device_discovery.continuous_monitoring(args.interval, args.duration)
            
            if args.save:
                self.device_discovery.save_results()
        except KeyboardInterrupt:
            print("\nDevice discovery interrupted by user.")
    
    def run_traffic_analysis(self, args):
        """Run traffic analysis module."""
        print("\n" + "="*80)
        print("Network Traffic Analysis")
        print("="*80)
        
        self.traffic_analyzer.check_root()
        
        try:
            if args.pcap:
                self.traffic_analyzer.analyze_pcap(args.pcap)
            else:
                self.traffic_analyzer.set_interface(args.interface)
                self.traffic_analyzer.live_display = args.live
                self.traffic_analyzer.start_capture(args.duration, args.filter, args.count)
            
            if args.save:
                self.traffic_analyzer.save_results()
        except KeyboardInterrupt:
            print("\nTraffic analysis interrupted by user.")
    
    def run_port_scan(self, args):
        """Run port scanner module."""
        print("\n" + "="*80)
        print("Network Port Scanner")
        print("="*80)
        
        self.port_scanner.check_root()
        
        # Add targets
        if args.target:
            self.port_scanner.add_target(args.target)
        
        if args.file:
            self.port_scanner.add_targets_from_file(args.file)
        
        if not self.port_scanner.targets:
            print("Error: No targets specified.")
            return
        
        # Parse ports
        ports = None
        if args.ports:
            try:
                ports = [int(p) for p in args.ports.split(',')]
            except ValueError:
                print("Error: Invalid port specification. Must be comma-separated integers.")
                return
        
        try:
            self.port_scanner.start_scan(args.type, ports, args.protocol, args.vulns)
            
            if args.save:
                self.port_scanner.save_results()
        except KeyboardInterrupt:
            print("\nPort scan interrupted by user.")
    
    def run_all_scans(self, args):
        """Run all scanning modules in sequence."""
        print("\n" + "="*80)
        print("WiFi Analyzer - Complete Network Analysis")
        print("="*80)
        
        # Check root privileges
        self.check_root()
        
        # Set up common arguments
        wifi_args = argparse.Namespace(
            interface=args.interface,
            time=args.duration,
            no_hop=False,
            save=args.save
        )
        
        device_args = argparse.Namespace(
            interface=args.interface,
            target=args.target,
            monitor=False,
            duration=None,
            interval=60,
            save=args.save
        )
        
        traffic_args = argparse.Namespace(
            interface=args.interface,
            duration=args.duration,
            filter=None,
            count=None,
            pcap=None,
            live=True,
            save=args.save
        )
        
        port_args = argparse.Namespace(
            target=args.target,
            file=None,
            ports=None,
            type='quick',
            protocol='tcp',
            vulns=True,
            save=args.save
        )
        
        try:
            # Run WiFi scan
            print("\nStarting WiFi network scan...")
            self.run_wifi_scan(wifi_args)
            
            # Run device discovery
            print("\nStarting device discovery...")
            self.run_device_discovery(device_args)
            
            # Run traffic analysis
            print("\nStarting traffic analysis...")
            self.run_traffic_analysis(traffic_args)
            
            # Run port scan
            if args.target:
                print("\nStarting port scan...")
                self.run_port_scan(port_args)
            else:
                print("\nSkipping port scan (no target specified).")
            
            print("\nAll scans completed!")
            print(f"Results saved to: {self.results_dir}" if args.save else "")
            
        except KeyboardInterrupt:
            print("\nAnalysis interrupted by user.")
    
    def run(self):
        """Run the WiFi Analyzer Tool based on command-line arguments."""
        args = self.parse_arguments()
        
        if args.command == 'wifi':
            self.run_wifi_scan(args)
        elif args.command == 'devices':
            self.run_device_discovery(args)
        elif args.command == 'traffic':
            self.run_traffic_analysis(args)
        elif args.command == 'ports':
            self.run_port_scan(args)
        elif args.command == 'all':
            self.run_all_scans(args)
        elif args.command == 'gui':
            self.launch_gui()
        else:
            print("Please specify a command. Use -h for help.")
    
    def launch_gui(self):
        """Launch the graphical user interface."""
        # Check root privileges
        self.check_root()
        
        # Create and start the GUI
        app = WiFiAnalyzerGUI(self.results_dir)
        app.run()

class WiFiAnalyzerGUI:
    """Graphical user interface for the WiFi Analyzer Tool."""
    
    def __init__(self, results_dir):
        self.results_dir = results_dir
        self.wifi_scanner = WiFiScanner()
        self.device_discovery = DeviceDiscovery()
        self.traffic_analyzer = TrafficAnalyzer()
        self.port_scanner = PortScanner()
        
        # Set save locations for all modules
        self.wifi_scanner.save_location = self.results_dir
        self.device_discovery.save_location = self.results_dir
        self.traffic_analyzer.save_location = self.results_dir
        self.port_scanner.save_location = self.results_dir
        
        # Initialize GUI components
        self.root = tk.Tk()
        self.root.title("WiFi Analyzer Tool")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Set up style
        self.style = ttk.Style()
        self.style.configure("TNotebook", background="#f0f0f0")
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", padding=6, relief="flat", background="#4CAF50", foreground="black")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("Header.TLabel", font=("Arial", 12, "bold"))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_wifi_tab()
        self.create_devices_tab()
        self.create_traffic_tab()
        self.create_ports_tab()
        self.create_results_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_wifi_tab(self):
        """Create the WiFi scanner tab."""
        wifi_frame = ttk.Frame(self.notebook)
        self.notebook.add(wifi_frame, text="WiFi Scanner")
        
        # Header
        header = ttk.Label(wifi_frame, text="WiFi Network Scanner", style="Header.TLabel")
        header.grid(row=0, column=0, columnspan=3, pady=10, sticky=tk.W)
        
        # Interface selection
        ttk.Label(wifi_frame, text="Wireless Interface:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.wifi_interface_var = tk.StringVar()
        self.wifi_interface_combo = ttk.Combobox(wifi_frame, textvariable=self.wifi_interface_var)
        self.wifi_interface_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Button(wifi_frame, text="Refresh", command=self.refresh_interfaces).grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        
        # Scan duration
        ttk.Label(wifi_frame, text="Scan Duration (seconds):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.wifi_duration_var = tk.IntVar(value=30)
        ttk.Spinbox(wifi_frame, from_=5, to=300, textvariable=self.wifi_duration_var, width=10).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Channel hopping
        self.wifi_hop_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(wifi_frame, text="Enable Channel Hopping", variable=self.wifi_hop_var).grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Save results
        self.wifi_save_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(wifi_frame, text="Save Results to File", variable=self.wifi_save_var).grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Start scan button
        ttk.Button(wifi_frame, text="Start WiFi Scan", command=self.start_wifi_scan).grid(row=5, column=0, columnspan=3, padx=5, pady=20)
        
        # Results area
        ttk.Label(wifi_frame, text="Scan Results:").grid(row=6, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.wifi_results = scrolledtext.ScrolledText(wifi_frame, width=80, height=20)
        self.wifi_results.grid(row=7, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)
        
        # Configure grid weights
        wifi_frame.columnconfigure(1, weight=1)
        wifi_frame.rowconfigure(7, weight=1)
    
    def create_devices_tab(self):
        """Create the device discovery tab."""
        devices_frame = ttk.Frame(self.notebook)
        self.notebook.add(devices_frame, text="Device Discovery")
        
        # Header
        header = ttk.Label(devices_frame, text="Network Device Discovery", style="Header.TLabel")
        header.grid(row=0, column=0, columnspan=3, pady=10, sticky=tk.W)
        
        # Interface selection
        ttk.Label(devices_frame, text="Network Interface:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.devices_interface_var = tk.StringVar()
        self.devices_interface_combo = ttk.Combobox(devices_frame, textvariable=self.devices_interface_var)
        self.devices_interface_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Target network
        ttk.Label(devices_frame, text="Target Network (CIDR):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.devices_target_var = tk.StringVar()
        ttk.Entry(devices_frame, textvariable=self.devices_target_var, width=20).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(devices_frame, text="(Leave blank for auto-detect)").grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)
        
        # Continuous monitoring
        self.devices_monitor_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(devices_frame, text="Enable Continuous Monitoring", variable=self.devices_monitor_var, command=self.toggle_monitoring_options).grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Monitoring options frame
        monitoring_frame = ttk.Frame(devices_frame)
        monitoring_frame.grid(row=4, column=0, columnspan=3, padx=20, pady=5, sticky=tk.W)
        
        ttk.Label(monitoring_frame, text="Interval (seconds):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.devices_interval_var = tk.IntVar(value=60)
        ttk.Spinbox(monitoring_frame, from_=10, to=300, textvariable=self.devices_interval_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(monitoring_frame, text="Duration (seconds):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.devices_duration_var = tk.IntVar(value=300)
        ttk.Spinbox(monitoring_frame, from_=60, to=3600, textvariable=self.devices_duration_var, width=10).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(monitoring_frame, text="(0 for unlimited)").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        
        # Save results
        self.devices_save_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(devices_frame, text="Save Results to File", variable=self.devices_save_var).grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Start scan button
        ttk.Button(devices_frame, text="Start Device Discovery", command=self.start_device_discovery).grid(row=6, column=0, columnspan=3, padx=5, pady=20)
        
        # Results area
        ttk.Label(devices_frame, text="Discovery Results:").grid(row=7, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.devices_results = scrolledtext.ScrolledText(devices_frame, width=80, height=20)
        self.devices_results.grid(row=8, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)
        
        # Configure grid weights
        devices_frame.columnconfigure(1, weight=1)
        devices_frame.rowconfigure(8, weight=1)
        
        # Initially disable monitoring options
        self.toggle_monitoring_options()
    
    def create_traffic_tab(self):
        """Create the traffic analysis tab."""
        traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(traffic_frame, text="Traffic Analysis")
        
        # Header
        header = ttk.Label(traffic_frame, text="Network Traffic Analysis", style="Header.TLabel")
        header.grid(row=0, column=0, columnspan=3, pady=10, sticky=tk.W)
        
        # Interface selection
        ttk.Label(traffic_frame, text="Network Interface:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.traffic_interface_var = tk.StringVar()
        self.traffic_interface_combo = ttk.Combobox(traffic_frame, textvariable=self.traffic_interface_var)
        self.traffic_interface_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Capture options
        ttk.Label(traffic_frame, text="Capture Duration (seconds):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.traffic_duration_var = tk.IntVar(value=60)
        ttk.Spinbox(traffic_frame, from_=10, to=600, textvariable=self.traffic_duration_var, width=10).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(traffic_frame, text="Packet Filter (BPF syntax):").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.traffic_filter_var = tk.StringVar()
        ttk.Entry(traffic_frame, textvariable=self.traffic_filter_var, width=30).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(traffic_frame, text="(e.g., 'port 80' or 'host 192.168.1.1')").grid(row=3, column=2, padx=5, pady=5, sticky=tk.W)
        
        # PCAP file analysis
        ttk.Label(traffic_frame, text="Analyze PCAP File:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.traffic_pcap_var = tk.StringVar()
        pcap_frame = ttk.Frame(traffic_frame)
        pcap_frame.grid(row=4, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(pcap_frame, textvariable=self.traffic_pcap_var, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Button(pcap_frame, text="Browse", command=self.browse_pcap).pack(side=tk.LEFT, padx=5)
        
        # Live display
        self.traffic_live_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(traffic_frame, text="Enable Live Statistics Display", variable=self.traffic_live_var).grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Save results
        self.traffic_save_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(traffic_frame, text="Save Results to File", variable=self.traffic_save_var).grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Start buttons
        button_frame = ttk.Frame(traffic_frame)
        button_frame.grid(row=7, column=0, columnspan=3, padx=5, pady=20)
        ttk.Button(button_frame, text="Start Capture", command=self.start_traffic_capture).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Analyze PCAP", command=self.analyze_pcap).pack(side=tk.LEFT, padx=10)
        
        # Results area
        ttk.Label(traffic_frame, text="Analysis Results:").grid(row=8, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.traffic_results = scrolledtext.ScrolledText(traffic_frame, width=80, height=20)
        self.traffic_results.grid(row=9, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)
        
        # Configure grid weights
        traffic_frame.columnconfigure(1, weight=1)
        traffic_frame.rowconfigure(9, weight=1)
    
    def create_ports_tab(self):
        """Create the port scanner tab."""
        ports_frame = ttk.Frame(self.notebook)
        self.notebook.add(ports_frame, text="Port Scanner")
        
        # Header
        header = ttk.Label(ports_frame, text="Network Port Scanner", style="Header.TLabel")
        header.grid(row=0, column=0, columnspan=3, pady=10, sticky=tk.W)
        
        # Target selection
        ttk.Label(ports_frame, text="Target (IP/Hostname/CIDR):").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.ports_target_var = tk.StringVar()
        ttk.Entry(ports_frame, textvariable=self.ports_target_var, width=30).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Target file
        ttk.Label(ports_frame, text="Target File:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        target_file_frame = ttk.Frame(ports_frame)
        target_file_frame.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W)
        self.ports_file_var = tk.StringVar()
        ttk.Entry(target_file_frame, textvariable=self.ports_file_var, width=30).pack(side=tk.LEFT, padx=5)
        ttk.Button(target_file_frame, text="Browse", command=self.browse_target_file).pack(side=tk.LEFT, padx=5)
        
        # Port range
        ttk.Label(ports_frame, text="Ports (comma-separated):").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.ports_range_var = tk.StringVar()
        ttk.Entry(ports_frame, textvariable=self.ports_range_var, width=30).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(ports_frame, text="(Leave blank for default)").grid(row=3, column=2, padx=5, pady=5, sticky=tk.W)
        
        # Scan type
        ttk.Label(ports_frame, text="Scan Type:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.ports_type_var = tk.StringVar(value="quick")
        scan_type_frame = ttk.Frame(ports_frame)
        scan_type_frame.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Radiobutton(scan_type_frame, text="Quick Scan", variable=self.ports_type_var, value="quick").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(scan_type_frame, text="Nmap Scan", variable=self.ports_type_var, value="nmap").pack(side=tk.LEFT, padx=5)
        
        # Protocol
        ttk.Label(ports_frame, text="Protocol:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.ports_protocol_var = tk.StringVar(value="tcp")
        protocol_frame = ttk.Frame(ports_frame)
        protocol_frame.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Radiobutton(protocol_frame, text="TCP", variable=self.ports_protocol_var, value="tcp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(protocol_frame, text="UDP", variable=self.ports_protocol_var, value="udp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(protocol_frame, text="Both", variable=self.ports_protocol_var, value="both").pack(side=tk.LEFT, padx=5)
        
        # Vulnerability checks
        self.ports_vulns_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ports_frame, text="Check for Vulnerabilities", variable=self.ports_vulns_var).grid(row=6, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Save results
        self.ports_save_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ports_frame, text="Save Results to File", variable=self.ports_save_var).grid(row=7, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W)
        
        # Start scan button
        ttk.Button(ports_frame, text="Start Port Scan", command=self.start_port_scan).grid(row=8, column=0, columnspan=3, padx=5, pady=20)
        
        # Results area
        ttk.Label(ports_frame, text="Scan Results:").grid(row=9, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.ports_results = scrolledtext.ScrolledText(ports_frame, width=80, height=20)
        self.ports_results.grid(row=10, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)
        
        # Configure grid weights
        ports_frame.columnconfigure(1, weight=1)
        ports_frame.rowconfigure(10, weight=1)
    
    def create_results_tab(self):
        """Create the results tab."""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Results")
        
        # Header
        header = ttk.Label(results_frame, text="Analysis Results", style="Header.TLabel")
        header.grid(row=0, column=0, columnspan=3, pady=10, sticky=tk.W)
        
        # Results directory
        ttk.Label(results_frame, text=f"Results Directory: {self.results_dir}").grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        # Results list
        ttk.Label(results_frame, text="Available Result Files:").grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        # Create a frame for the listbox and scrollbar
        list_frame = ttk.Frame(results_frame)
        list_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Listbox
        self.results_listbox = tk.Listbox(list_frame, width=80, height=10, yscrollcommand=scrollbar.set)
        self.results_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.results_listbox.yview)
        
        # Buttons
        button_frame = ttk.Frame(results_frame)
        button_frame.grid(row=4, column=0, columnspan=3, padx=5, pady=10)
        ttk.Button(button_frame, text="Refresh List", command=self.refresh_results_list).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="View Selected", command=self.view_selected_result).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Delete Selected", command=self.delete_selected_result).pack(side=tk.LEFT, padx=10)
        
        # Result content
        ttk.Label(results_frame, text="File Content:").grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.result_content = scrolledtext.ScrolledText(results_frame, width=80, height=20)
        self.result_content.grid(row=6, column=0, columnspan=3, padx=5, pady=5, sticky=tk.NSEW)
        
        # Configure grid weights
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(3, weight=1)
        results_frame.rowconfigure(6, weight=2)
        
        # Initial refresh
        self.refresh_results_list()
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces."""
        try:
            # Get wireless interfaces
            wifi_interfaces = self.wifi_scanner.get_interfaces()
            self.wifi_interface_combo['values'] = wifi_interfaces
            if wifi_interfaces:
                self.wifi_interface_var.set(wifi_interfaces[0])
            
            # Get all interfaces
            all_interfaces = self.device_discovery.get_interfaces()
            self.devices_interface_combo['values'] = all_interfaces
            self.traffic_interface_combo['values'] = all_interfaces
            if all_interfaces:
                # Set default to first non-loopback interface
                default_iface = next((iface for iface in all_interfaces if iface != 'lo'), all_interfaces[0])
                self.devices_interface_var.set(default_iface)
                self.traffic_interface_var.set(default_iface)
            
            self.status_var.set("Interfaces refreshed")
        except Exception as e:
            self.status_var.set(f"Error refreshing interfaces: {e}")
    
    def toggle_monitoring_options(self):
        """Enable or disable monitoring options based on checkbox state."""
        # This would be implemented to enable/disable the monitoring options
        # based on the state of the continuous monitoring checkbox
        pass
    
    def browse_pcap(self):
        """Browse for a PCAP file."""
        filename = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=(("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*"))
        )
        if filename:
            self.traffic_pcap_var.set(filename)
    
    def browse_target_file(self):
        """Browse for a target file."""
        filename = filedialog.askopenfilename(
            title="Select Target File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        if filename:
            self.ports_file_var.set(filename)
    
    def refresh_results_list(self):
        """Refresh the list of result files."""
        self.results_listbox.delete(0, tk.END)
        try:
            files = sorted([f for f in os.listdir(self.results_dir) if f.endswith('.json')])
            for file in files:
                self.results_listbox.insert(tk.END, file)
            self.status_var.set(f"Found {len(files)} result files")
        except Exception as e:
            self.status_var.set(f"Error refreshing results list: {e}")
    
    def view_selected_result(self):
        """View the content of the selected result file."""
        selection = self.results_listbox.curselection()
        if not selection:
            messagebox.showinfo("Selection Required", "Please select a result file to view.")
            return
        
        filename = self.results_listbox.get(selection[0])
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            self.result_content.delete(1.0, tk.END)
            self.result_content.insert(tk.END, content)
            self.status_var.set(f"Loaded file: {filename}")
        except Exception as e:
            self.status_var.set(f"Error loading file: {e}")
    
    def delete_selected_result(self):
        """Delete the selected result file."""
        selection = self.results_listbox.curselection()
        if not selection:
            messagebox.showinfo("Selection Required", "Please select a result file to delete.")
            return
        
        filename = self.results_listbox.get(selection[0])
        filepath = os.path.join(self.results_dir, filename)
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {filename}?"):
            try:
                os.remove(filepath)
                self.refresh_results_list()
                self.result_content.delete(1.0, tk.END)
                self.status_var.set(f"Deleted file: {filename}")
            except Exception as e:
                self.status_var.set(f"Error deleting file: {e}")
    
    def redirect_output(self, text_widget):
        """Redirect stdout and stderr to a text widget."""
        class TextRedirector:
            def __init__(self, text_widget):
                self.text_widget = text_widget
                self.buffer = ""
            
            def write(self, string):
                self.buffer += string
                self.text_widget.delete(1.0, tk.END)
                self.text_widget.insert(tk.END, self.buffer)
                self.text_widget.see(tk.END)
            
            def flush(self):
                pass
        
        sys.stdout = TextRedirector(text_widget)
        sys.stderr = TextRedirector(text_widget)
    
    def restore_output(self):
        """Restore stdout and stderr to their original values."""
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
    
    def start_wifi_scan(self):
        """Start WiFi scanning in a separate thread."""
        # Clear results
        self.wifi_results.delete(1.0, tk.END)
        
        # Get parameters
        interface = self.wifi_interface_var.get()
        duration = self.wifi_duration_var.get()
        channel_hop = self.wifi_hop_var.get()
        save_results = self.wifi_save_var.get()
        
        if not interface:
            messagebox.showerror("Error", "Please select a wireless interface.")
            return
        
        # Update status
        self.status_var.set(f"Starting WiFi scan on {interface}...")
        
        # Create thread function
        def scan_thread():
            try:
                # Redirect output
                self.redirect_output(self.wifi_results)
                
                # Configure scanner
                self.wifi_scanner.set_interface(interface)
                self.wifi_scanner.channel_hop = channel_hop
                
                # Start scan
                self.wifi_scanner.start_scan(duration)
                
                # Save results if requested
                if save_results:
                    self.wifi_scanner.save_results()
                
                # Update status
                self.status_var.set("WiFi scan completed")
            except Exception as e:
                self.status_var.set(f"Error during WiFi scan: {e}")
            finally:
                # Clean up
                self.wifi_scanner.cleanup()
                self.restore_output()
        
        # Start thread
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def start_device_discovery(self):
        """Start device discovery in a separate thread."""
        # Clear results
        self.devices_results.delete(1.0, tk.END)
        
        # Get parameters
        interface = self.devices_interface_var.get()
        target = self.devices_target_var.get() or None
        monitor = self.devices_monitor_var.get()
        interval = self.devices_interval_var.get()
        duration = self.devices_duration_var.get() if monitor else None
        save_results = self.devices_save_var.get()
        
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return
        
        # Update status
        self.status_var.set(f"Starting device discovery on {interface}...")
        
        # Create thread function
        def discovery_thread():
            try:
                # Redirect output
                self.redirect_output(self.devices_results)
                
                # Configure discovery
                self.device_discovery.set_interface(interface)
                
                # Get network info and start scan
                self.device_discovery.get_network_info()
                self.device_discovery.arp_scan(target)
                
                # Start monitoring if requested
                if monitor:
                    self.device_discovery.continuous_monitoring(interval, duration)
                
                # Save results if requested
                if save_results:
                    self.device_discovery.save_results()
                
                # Update status
                self.status_var.set("Device discovery completed")
            except Exception as e:
                self.status_var.set(f"Error during device discovery: {e}")
            finally:
                self.restore_output()
        
        # Start thread
        threading.Thread(target=discovery_thread, daemon=True).start()
    
    def start_traffic_capture(self):
        """Start traffic capture in a separate thread."""
        # Clear results
        self.traffic_results.delete(1.0, tk.END)
        
        # Get parameters
        interface = self.traffic_interface_var.get()
        duration = self.traffic_duration_var.get()
        packet_filter = self.traffic_filter_var.get() or None
        live_display = self.traffic_live_var.get()
        save_results = self.traffic_save_var.get()
        
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return
        
        # Update status
        self.status_var.set(f"Starting traffic capture on {interface}...")
        
        # Create thread function
        def capture_thread():
            try:
                # Redirect output
                self.redirect_output(self.traffic_results)
                
                # Configure analyzer
                self.traffic_analyzer.set_interface(interface)
                self.traffic_analyzer.live_display = live_display
                
                # Start capture
                self.traffic_analyzer.start_capture(duration, packet_filter)
                
                # Save results if requested
                if save_results:
                    self.traffic_analyzer.save_results()
                
                # Update status
                self.status_var.set("Traffic capture completed")
            except Exception as e:
                self.status_var.set(f"Error during traffic capture: {e}")
            finally:
                self.restore_output()
        
        # Start thread
        threading.Thread(target=capture_thread, daemon=True).start()
    
    def analyze_pcap(self):
        """Analyze a PCAP file in a separate thread."""
        # Clear results
        self.traffic_results.delete(1.0, tk.END)
        
        # Get parameters
        pcap_file = self.traffic_pcap_var.get()
        save_results = self.traffic_save_var.get()
        
        if not pcap_file:
            messagebox.showerror("Error", "Please select a PCAP file to analyze.")
            return
        
        if not os.path.exists(pcap_file):
            messagebox.showerror("Error", f"PCAP file not found: {pcap_file}")
            return
        
        # Update status
        self.status_var.set(f"Analyzing PCAP file: {pcap_file}...")
        
        # Create thread function
        def analyze_thread():
            try:
                # Redirect output
                self.redirect_output(self.traffic_results)
                
                # Analyze PCAP
                self.traffic_analyzer.analyze_pcap(pcap_file)
                
                # Save results if requested
                if save_results:
                    self.traffic_analyzer.save_results()
                
                # Update status
                self.status_var.set("PCAP analysis completed")
            except Exception as e:
                self.status_var.set(f"Error during PCAP analysis: {e}")
            finally:
                self.restore_output()
        
        # Start thread
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def start_port_scan(self):
        """Start port scanning in a separate thread."""
        # Clear results
        self.ports_results.delete(1.0, tk.END)
        
        # Get parameters
        target = self.ports_target_var.get()
        target_file = self.ports_file_var.get()
        ports_str = self.ports_range_var.get()
        scan_type = self.ports_type_var.get()
        protocol = self.ports_protocol_var.get()
        check_vulns = self.ports_vulns_var.get()
        save_results = self.ports_save_var.get()
        
        if not target and not target_file:
            messagebox.showerror("Error", "Please specify a target or target file.")
            return
        
        # Parse ports
        ports = None
        if ports_str:
            try:
                ports = [int(p) for p in ports_str.split(',')]
            except ValueError:
                messagebox.showerror("Error", "Invalid port specification. Must be comma-separated integers.")
                return
        
        # Update status
        self.status_var.set("Starting port scan...")
        
        # Create thread function
        def scan_thread():
            try:
                # Redirect output
                self.redirect_output(self.ports_results)
                
                # Add targets
                if target:
                    self.port_scanner.add_target(target)
                
                if target_file and os.path.exists(target_file):
                    self.port_scanner.add_targets_from_file(target_file)
                
                if not self.port_scanner.targets:
                    print("Error: No valid targets specified.")
                    return
                
                # Start scan
                self.port_scanner.start_scan(scan_type, ports, protocol, check_vulns)
                
                # Save results if requested
                if save_results:
                    self.port_scanner.save_results()
                
                # Update status
                self.status_var.set("Port scan completed")
            except Exception as e:
                self.status_var.set(f"Error during port scan: {e}")
            finally:
                self.restore_output()
        
        # Start thread
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def run(self):
        """Run the GUI application."""
        # Refresh interfaces
        self.refresh_interfaces()
        
        # Start the main loop
        self.root.mainloop()

def main():
    """Main function to run the WiFi Analyzer Tool."""
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root.")
        print("Please run with sudo or as root user.")
        sys.exit(1)
    
    # Parse command-line arguments
    cli = WiFiAnalyzerCLI()
    cli.run()

if __name__ == "__main__":
    main()
