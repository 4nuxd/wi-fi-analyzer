# WiFi Analyzer Tool

A comprehensive Python tool for WiFi network analysis, device discovery, traffic monitoring, and port scanning.

## Features

- **WiFi Scanner**: Scan for WiFi networks, detect signal strength, encryption types, and channel information
- **Device Discovery**: Find devices connected to your network, identify vendors, and monitor for new connections
- **Traffic Analysis**: Capture and analyze network traffic, detect protocols, and monitor HTTP requests
- **Port Scanner**: Scan for open ports on network devices, identify services, and check for vulnerabilities
- **Unified Interface**: Both command-line and graphical interfaces available

## Requirements

- Linux operating system (tested on Ubuntu)
- Python 3.6+
- Root/sudo privileges
- Required Python packages:
  - scapy
  - netifaces
  - psutil
  - matplotlib
  - python-nmap
  - pyshark
  - tkinter (for GUI)

## Installation

1. Ensure you have the required system dependencies:

```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-tk python3-dev libpcap-dev
```

2. Install the required Python packages:

```bash
pip3 install scapy netifaces psutil matplotlib python-nmap pyshark
```

3. Clone or download this repository:

```bash
git clone https://github.com/yourusername/wifi-analyzer.git
cd wifi-analyzer
```

4. Make the scripts executable:

```bash
chmod +x wifi_scanner.py device_discovery.py traffic_analyzer.py port_scanner.py wifi_analyzer.py
```

## Usage

### Command-Line Interface

The tool provides a unified command-line interface with several subcommands:

#### WiFi Scanner

```bash
sudo ./wifi_analyzer.py wifi [-i INTERFACE] [-t TIME] [-n] [-s]
```

Options:
- `-i, --interface`: Wireless interface to use
- `-t, --time`: Scan duration in seconds (default: 30)
- `-n, --no-hop`: Disable channel hopping
- `-s, --save`: Save results to file

#### Device Discovery

```bash
sudo ./wifi_analyzer.py devices [-i INTERFACE] [-t TARGET] [-m] [-d DURATION] [-n INTERVAL] [-s]
```

Options:
- `-i, --interface`: Network interface to use
- `-t, --target`: Target network to scan (CIDR notation)
- `-m, --monitor`: Enable continuous monitoring
- `-d, --duration`: Monitoring duration in seconds
- `-n, --interval`: Monitoring interval in seconds (default: 60)
- `-s, --save`: Save results to file

#### Traffic Analysis

```bash
sudo ./wifi_analyzer.py traffic [-i INTERFACE] [-d DURATION] [-f FILTER] [-c COUNT] [-p PCAP] [-l] [-s]
```

Options:
- `-i, --interface`: Network interface to use
- `-d, --duration`: Capture duration in seconds
- `-f, --filter`: Packet filter expression (BPF syntax)
- `-c, --count`: Maximum number of packets to capture
- `-p, --pcap`: Analyze existing PCAP file instead of capturing
- `-l, --live`: Enable live statistics display
- `-s, --save`: Save analysis results to file

#### Port Scanner

```bash
sudo ./wifi_analyzer.py ports [-t TARGET] [-f FILE] [-p PORTS] [-T TYPE] [-P PROTOCOL] [-v] [-s]
```

Options:
- `-t, --target`: Target IP, hostname, or network (CIDR notation)
- `-f, --file`: File containing targets, one per line
- `-p, --ports`: Ports to scan (comma-separated, e.g., 22,80,443)
- `-T, --type`: Scan type (quick or nmap, default: quick)
- `-P, --protocol`: Protocol to scan (tcp, udp, or both, default: tcp)
- `-v, --vulns`: Check for vulnerabilities
- `-s, --save`: Save results to file

#### All-in-One Scan

```bash
sudo ./wifi_analyzer.py all [-i INTERFACE] [-t TARGET] [-d DURATION] [-s]
```

Options:
- `-i, --interface`: Network interface to use
- `-t, --target`: Target network to scan (CIDR notation)
- `-d, --duration`: Scan duration for each module in seconds (default: 30)
- `-s, --save`: Save all results to files

### Graphical User Interface

To launch the graphical user interface:

```bash
sudo ./wifi_analyzer.py gui
```

The GUI provides access to all features through a tabbed interface:
- WiFi Scanner tab: Scan for WiFi networks
- Device Discovery tab: Find devices on your network
- Traffic Analysis tab: Capture and analyze network traffic
- Port Scanner tab: Scan for open ports and services
- Results tab: View and manage saved results

## Examples

### Scan for WiFi networks for 60 seconds and save results

```bash
sudo ./wifi_analyzer.py wifi -i wlan0 -t 60 -s
```

### Discover devices on the 192.168.1.0/24 network

```bash
sudo ./wifi_analyzer.py devices -i eth0 -t 192.168.1.0/24 -s
```

### Capture HTTP traffic for 120 seconds

```bash
sudo ./wifi_analyzer.py traffic -i eth0 -d 120 -f "port 80" -l -s
```

### Scan for open ports on a specific host

```bash
sudo ./wifi_analyzer.py ports -t 192.168.1.100 -p 22,80,443,3389 -v -s
```

### Run all scans on the default network

```bash
sudo ./wifi_analyzer.py all -i wlan0 -d 60 -s
```

## Security and Ethical Considerations

This tool is intended for network administrators and security professionals to analyze their own networks or networks they have permission to test. Unauthorized scanning of networks may violate laws and regulations.

- Always obtain proper authorization before scanning any network
- Be aware that some scanning techniques may disrupt network services
- Handle any sensitive information discovered with appropriate care
- Do not use this tool for any malicious purposes

## Limitations

- Some features require specific hardware support (e.g., WiFi scanning requires a wireless interface that supports monitor mode)
- Performance may vary depending on system resources and network size
- The tool is designed for Linux systems and may not work on other operating systems
- Some advanced features require additional tools (e.g., nmap for comprehensive port scanning)

## Troubleshooting

### Common Issues

1. **"Error: This script must be run as root"**
   - Run the tool with sudo or as the root user

2. **"No wireless interfaces found"**
   - Ensure your wireless interface is enabled and recognized by the system
   - Try running `iwconfig` to list available wireless interfaces

3. **"Failed to enable monitor mode"**
   - Not all wireless adapters support monitor mode
   - Try using a different wireless adapter

4. **"Error during capture"**
   - Check if another application is using the selected interface
   - Verify you have the required permissions

### Getting Help

If you encounter any issues not covered in this documentation, please:
1. Check the error message for specific details
2. Verify you have all required dependencies installed
3. Ensure you're running the latest version of the tool

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Scapy project for packet manipulation capabilities
- Nmap for port scanning functionality
- PyShark for packet capture and analysis
- All other open-source libraries used in this project
