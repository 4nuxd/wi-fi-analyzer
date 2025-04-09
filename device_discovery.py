#!/usr/bin/env python3
"""
Device Discovery Module - Part of the WiFi Analyzer Tool
This module provides functionality to discover devices connected to a network and analyze their activities.
"""

import os
import sys
import time
import argparse
import subprocess
from datetime import datetime
import scapy.all as scapy
import netifaces
import json
import re
import requests
from mac_vendor_lookup import MacLookup

class DeviceDiscovery:
    def __init__(self):
        self.devices = {}
        self.interface = None
        self.network = None
        self.gateway_ip = None
        self.local_ip = None
        self.save_location = None
        self.mac_lookup = MacLookup()
        self.scan_active = False
    
    def check_root(self):
        """Check if the script is running with root privileges."""
        if os.geteuid() != 0:
            print("Error: This script must be run as root.")
            print("Please run with sudo or as root user.")
            sys.exit(1)
    
    def get_interfaces(self):
        """Get all network interfaces."""
        return netifaces.interfaces()
    
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
                
                # Check if interface has an IPv4 address
                if netifaces.AF_INET in netifaces.ifaddresses(iface):
                    self.interface = iface
                    print(f"Using network interface: {self.interface}")
                    return
            
            # If no suitable interface found, use the first non-loopback
            for iface in available_interfaces:
                if iface != "lo":
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
    
    def get_network_info(self):
        """Get network information for the selected interface."""
        if self.interface is None:
            print("Error: No interface selected.")
            return False
        
        try:
            # Get IP address and netmask
            if netifaces.AF_INET in netifaces.ifaddresses(self.interface):
                addr_info = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]
                self.local_ip = addr_info['addr']
                netmask = addr_info['netmask']
                
                # Calculate network address
                ip_parts = [int(part) for part in self.local_ip.split('.')]
                mask_parts = [int(part) for part in netmask.split('.')]
                network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                
                # Calculate CIDR notation
                cidr = sum(bin(part).count('1') for part in mask_parts)
                
                self.network = f"{'.'.join(str(part) for part in network_parts)}/{cidr}"
                
                # Get default gateway
                gateways = netifaces.gateways()
                if netifaces.AF_INET in gateways['default']:
                    self.gateway_ip = gateways['default'][netifaces.AF_INET][0]
                
                print(f"Local IP: {self.local_ip}")
                print(f"Network: {self.network}")
                print(f"Gateway: {self.gateway_ip}")
                return True
            else:
                print(f"Error: No IPv4 address assigned to {self.interface}")
                return False
        except Exception as e:
            print(f"Error getting network information: {e}")
            return False
    
    def get_vendor(self, mac_address):
        """Get vendor information for a MAC address."""
        try:
            vendor = self.mac_lookup.lookup(mac_address)
            return vendor
        except:
            return "Unknown"
    
    def arp_scan(self, target=None):
        """Perform ARP scan to discover devices on the network."""
        if target is None:
            if self.network is None:
                if not self.get_network_info():
                    return
            target = self.network
        
        print(f"\nScanning for devices on {target}...")
        
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=target)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Send packets and receive responses
        try:
            answered, _ = scapy.srp(arp_request_broadcast, timeout=3, verbose=0, iface=self.interface)
            
            print("-" * 80)
            print(f"{'IP Address':<16} {'MAC Address':<18} {'Vendor':<30} {'Status'}")
            print("-" * 80)
            
            # Process responses
            for sent, received in answered:
                mac_address = received.hwsrc
                ip_address = received.psrc
                
                # Get vendor information
                vendor = self.get_vendor(mac_address)
                
                # Determine if it's the gateway
                is_gateway = (ip_address == self.gateway_ip)
                status = "Gateway" if is_gateway else "Host"
                
                # Store device information
                self.devices[mac_address] = {
                    'ip_address': ip_address,
                    'vendor': vendor,
                    'is_gateway': is_gateway,
                    'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'status': status
                }
                
                # Print device information
                print(f"{ip_address:<16} {mac_address:<18} {vendor:<30} {status}")
            
            print(f"\nDiscovered {len(self.devices)} devices on the network.")
            
        except Exception as e:
            print(f"Error during ARP scan: {e}")
    
    def continuous_monitoring(self, interval=60, duration=None):
        """Continuously monitor for new devices on the network."""
        if not self.devices:
            self.arp_scan()
        
        print(f"\nStarting continuous device monitoring (interval: {interval}s)...")
        print("Press Ctrl+C to stop monitoring.")
        
        start_time = time.time()
        self.scan_active = True
        
        try:
            while self.scan_active:
                # Check if duration is set and exceeded
                if duration and (time.time() - start_time) > duration:
                    print(f"\nMonitoring duration of {duration}s reached.")
                    break
                
                # Wait for the specified interval
                time.sleep(interval)
                
                # Store current devices for comparison
                previous_devices = set(self.devices.keys())
                
                # Perform a new scan
                arp_request = scapy.ARP(pdst=self.network)
                broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast/arp_request
                
                answered, _ = scapy.srp(arp_request_broadcast, timeout=3, verbose=0, iface=self.interface)
                
                # Process responses
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                current_devices = set()
                
                for sent, received in answered:
                    mac_address = received.hwsrc
                    ip_address = received.psrc
                    current_devices.add(mac_address)
                    
                    if mac_address in self.devices:
                        # Update existing device
                        self.devices[mac_address]['last_seen'] = current_time
                        
                        # Check if IP changed
                        if self.devices[mac_address]['ip_address'] != ip_address:
                            print(f"[{current_time}] Device {mac_address} ({self.devices[mac_address]['vendor']}) changed IP: {self.devices[mac_address]['ip_address']} -> {ip_address}")
                            self.devices[mac_address]['ip_address'] = ip_address
                    else:
                        # New device found
                        vendor = self.get_vendor(mac_address)
                        is_gateway = (ip_address == self.gateway_ip)
                        status = "Gateway" if is_gateway else "Host"
                        
                        self.devices[mac_address] = {
                            'ip_address': ip_address,
                            'vendor': vendor,
                            'is_gateway': is_gateway,
                            'first_seen': current_time,
                            'last_seen': current_time,
                            'status': status
                        }
                        
                        print(f"[{current_time}] New device detected: {ip_address} ({mac_address}) - {vendor}")
                
                # Check for devices that disappeared
                disappeared = previous_devices - current_devices
                for mac in disappeared:
                    print(f"[{current_time}] Device disappeared: {self.devices[mac]['ip_address']} ({mac}) - {self.devices[mac]['vendor']}")
                    self.devices[mac]['status'] = "Offline"
                
                # Print periodic summary
                print(f"[{current_time}] Active devices: {len(current_devices)}/{len(self.devices)}")
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
        except Exception as e:
            print(f"\nError during monitoring: {e}")
        finally:
            self.scan_active = False
    
    def save_results(self, filename=None):
        """Save device discovery results to a file."""
        if not self.devices:
            print("No devices to save.")
            return
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"device_discovery_{timestamp}.json"
        
        if self.save_location:
            filename = os.path.join(self.save_location, filename)
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.devices, f, indent=4)
            print(f"Device discovery results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(description='Network Device Discovery')
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('-t', '--target', help='Target network to scan (CIDR notation, e.g., 192.168.1.0/24)')
    parser.add_argument('-m', '--monitor', action='store_true', help='Enable continuous monitoring')
    parser.add_argument('-d', '--duration', type=int, help='Monitoring duration in seconds')
    parser.add_argument('-n', '--interval', type=int, default=60, help='Monitoring interval in seconds')
    parser.add_argument('-s', '--save', action='store_true', help='Save results to file')
    parser.add_argument('-o', '--output', help='Output file location')
    
    args = parser.parse_args()
    
    discovery = DeviceDiscovery()
    discovery.check_root()
    discovery.set_interface(args.interface)
    
    if args.output:
        discovery.save_location = args.output
    
    try:
        discovery.get_network_info()
        discovery.arp_scan(args.target)
        
        if args.monitor:
            discovery.continuous_monitoring(args.interval, args.duration)
        
        if args.save:
            discovery.save_results()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user.")

if __name__ == "__main__":
    main()
