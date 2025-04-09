#!/usr/bin/env python3
"""
WiFi Scanner Module - Part of the WiFi Analyzer Tool
This module provides functionality to scan for WiFi networks and analyze their properties.
"""

import os
import sys
import time
import argparse
import subprocess
from datetime import datetime
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import netifaces
import json

class WiFiScanner:
    def __init__(self):
        self.networks = {}
        self.interface = None
        self.monitor_mode = False
        self.channel_hop = True
        self.save_location = None
    
    def check_root(self):
        """Check if the script is running with root privileges."""
        if os.geteuid() != 0:
            print("Error: This script must be run as root.")
            print("Please run with sudo or as root user.")
            sys.exit(1)
    
    def get_interfaces(self):
        """Get all wireless interfaces."""
        interfaces = []
        for iface in netifaces.interfaces():
            # Check if this is a wireless interface
            try:
                output = subprocess.check_output(["iwconfig", iface], stderr=subprocess.STDOUT).decode()
                if "IEEE 802.11" in output:
                    interfaces.append(iface)
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        return interfaces
    
    def set_interface(self, interface=None):
        """Set the wireless interface to use."""
        available_interfaces = self.get_interfaces()
        
        if not available_interfaces:
            print("Error: No wireless interfaces found.")
            sys.exit(1)
        
        if interface is None:
            # If no interface specified, use the first available one
            self.interface = available_interfaces[0]
            print(f"Using wireless interface: {self.interface}")
        elif interface in available_interfaces:
            self.interface = interface
            print(f"Using wireless interface: {self.interface}")
        else:
            print(f"Error: Interface {interface} not found or not a wireless interface.")
            print(f"Available wireless interfaces: {', '.join(available_interfaces)}")
            sys.exit(1)
    
    def enable_monitor_mode(self):
        """Enable monitor mode on the selected interface."""
        if self.interface is None:
            print("Error: No interface selected.")
            return False
        
        try:
            # Check if already in monitor mode
            output = subprocess.check_output(["iwconfig", self.interface], stderr=subprocess.STDOUT).decode()
            if "Mode:Monitor" in output:
                print(f"Interface {self.interface} is already in monitor mode.")
                self.monitor_mode = True
                return True
            
            # Disable the interface
            subprocess.run(["ifconfig", self.interface, "down"], check=True)
            
            # Set monitor mode
            subprocess.run(["iwconfig", self.interface, "mode", "monitor"], check=True)
            
            # Enable the interface
            subprocess.run(["ifconfig", self.interface, "up"], check=True)
            
            # Verify monitor mode is enabled
            output = subprocess.check_output(["iwconfig", self.interface], stderr=subprocess.STDOUT).decode()
            if "Mode:Monitor" in output:
                print(f"Successfully enabled monitor mode on {self.interface}")
                self.monitor_mode = True
                return True
            else:
                print(f"Failed to enable monitor mode on {self.interface}")
                return False
        except subprocess.CalledProcessError as e:
            print(f"Error enabling monitor mode: {e}")
            return False
    
    def disable_monitor_mode(self):
        """Disable monitor mode and restore interface to managed mode."""
        if self.interface is None or not self.monitor_mode:
            return
        
        try:
            # Disable the interface
            subprocess.run(["ifconfig", self.interface, "down"], check=True)
            
            # Set managed mode
            subprocess.run(["iwconfig", self.interface, "mode", "managed"], check=True)
            
            # Enable the interface
            subprocess.run(["ifconfig", self.interface, "up"], check=True)
            
            print(f"Disabled monitor mode on {self.interface}")
            self.monitor_mode = False
        except subprocess.CalledProcessError as e:
            print(f"Error disabling monitor mode: {e}")
    
    def channel_hopper(self):
        """Hop through different channels to capture more networks."""
        import threading
        
        def hop_channels():
            channels = range(1, 14)  # Channels 1-13
            while self.channel_hop:
                for channel in channels:
                    try:
                        subprocess.run(["iwconfig", self.interface, "channel", str(channel)], 
                                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        time.sleep(0.5)  # Stay on each channel for 0.5 seconds
                    except subprocess.CalledProcessError:
                        continue
        
        # Start channel hopping in a separate thread
        hopper_thread = threading.Thread(target=hop_channels)
        hopper_thread.daemon = True
        hopper_thread.start()
    
    def packet_handler(self, packet):
        """Process captured packets to extract WiFi network information."""
        if not packet.haslayer(Dot11Beacon):
            return
        
        # Extract the MAC address of the network
        bssid = packet[Dot11].addr2
        if bssid not in self.networks:
            self.networks[bssid] = {}
        
        # Extract network name (SSID)
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
        if not ssid:
            ssid = "Hidden SSID"
        
        # Get the channel
        try:
            channel = int(ord(packet[Dot11Elt:3].info))
        except:
            channel = 0
        
        # Get signal strength (RSSI)
        try:
            rssi = packet.dBm_AntSignal
        except:
            rssi = -100  # Default value if not available
        
        # Determine encryption type
        capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        encryption = "Open"
        
        if 'privacy' in capability:
            # Check for WPA/WPA2
            crypto = set()
            for element in packet[Dot11Elt:]:
                if element.ID == 48:  # RSN (WPA2) element ID
                    encryption = "WPA2"
                elif element.ID == 221 and element.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                    encryption = "WPA"
            
            if encryption == "Open":
                encryption = "WEP"  # If privacy bit is set but no WPA/WPA2, it's WEP
        
        # Update network information
        self.networks[bssid].update({
            'ssid': ssid,
            'channel': channel,
            'rssi': rssi,
            'encryption': encryption,
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        # Print network information
        print(f"SSID: {ssid:<30} Channel: {channel:<3} RSSI: {rssi:<4} Encryption: {encryption:<5} BSSID: {bssid}")
    
    def start_scan(self, duration=30):
        """Start scanning for WiFi networks."""
        if not self.monitor_mode:
            if not self.enable_monitor_mode():
                return
        
        print(f"\nScanning for WiFi networks on {self.interface} for {duration} seconds...")
        print("-" * 80)
        print(f"{'SSID':<30} {'Channel':<8} {'RSSI':<6} {'Encryption':<10} {'BSSID':<18}")
        print("-" * 80)
        
        # Start channel hopping if enabled
        if self.channel_hop:
            self.channel_hopper()
        
        # Start packet capture
        try:
            scapy.sniff(iface=self.interface, prn=self.packet_handler, timeout=duration)
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
        except Exception as e:
            print(f"\nError during scan: {e}")
        finally:
            # Stop channel hopping
            self.channel_hop = False
            
            # Print summary
            print("\nScan complete!")
            print(f"Discovered {len(self.networks)} networks.")
    
    def save_results(self, filename=None):
        """Save scan results to a file."""
        if not self.networks:
            print("No networks to save.")
            return
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"wifi_scan_{timestamp}.json"
        
        if self.save_location:
            filename = os.path.join(self.save_location, filename)
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.networks, f, indent=4)
            print(f"Scan results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")
    
    def cleanup(self):
        """Clean up resources and restore interface state."""
        self.disable_monitor_mode()

def main():
    parser = argparse.ArgumentParser(description='WiFi Network Scanner')
    parser.add_argument('-i', '--interface', help='Wireless interface to use')
    parser.add_argument('-t', '--time', type=int, default=30, help='Scan duration in seconds')
    parser.add_argument('-s', '--save', action='store_true', help='Save results to file')
    parser.add_argument('-o', '--output', help='Output file location')
    parser.add_argument('-n', '--no-hop', action='store_true', help='Disable channel hopping')
    
    args = parser.parse_args()
    
    scanner = WiFiScanner()
    scanner.check_root()
    scanner.set_interface(args.interface)
    
    if args.no_hop:
        scanner.channel_hop = False
    
    if args.output:
        scanner.save_location = args.output
    
    try:
        scanner.start_scan(args.time)
        if args.save:
            scanner.save_results()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user.")
    finally:
        scanner.cleanup()

if __name__ == "__main__":
    main()
