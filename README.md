# Network Packet Detector

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Scapy](https://img.shields.io/badge/Scapy-Installed-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

A powerful and customizable network packet sniffer and intrusion detection script built with Python and Scapy. This tool analyzes network traffic in real-time to detect a variety of suspicious activities, including port scans, SYN floods, brute-force attacks, and common web application exploits.

## Features

* **Real-time Packet Analysis:** Sniffs network traffic on a specified interface.
* **Port Scan Detection:**
    * **Vertical Scans:** Detects when a single source IP scans a large number of ports on a single destination.
    * **Horizontal Scans:** Detects when a single source IP scans multiple hosts.
* **SYN Flood Detection:** Identifies a large volume of SYN packets from a single source, a classic Denial-of-Service (DoS) attack.
* **Brute-Force Detection:** Monitors for repeated connection attempts to specific services, such as SSH (Port 22).
* **Malicious Port Alerting:** Flags traffic to/from a predefined list of known malicious or high-risk ports.
* **Web Attack Detection:** Analyzes HTTP payloads for signatures of:
    * **SQL Injection:** Detects common keywords and patterns like `UNION SELECT`, `xp_cmdshell`, and `WAITFOR DELAY`.
    * **Cross-Site Scripting (XSS):** Identifies script tags and suspicious JavaScript event handlers.
    * **Path Traversal:** Flags attempts to access sensitive files like `/etc/passwd` or `boot.ini`.
* **Malformed Packet Detection:** Basic checks for unusual packet headers (e.g., invalid TCP data offset).
* **DNS Tunneling Heuristic:** Flags unusually long DNS queries that could indicate data exfiltration.
* **Customizable Thresholds:** Easily adjust detection sensitivity for floods and scans.

## Prerequisites

Before you can run the script, you need to have the following installed:

* **Python 3.x**
* **Scapy:** A powerful interactive packet manipulation program.
* **libpcap (or Npcap on Windows):** Scapy requires a packet capture library.
    * **On Debian/Ubuntu:** `sudo apt-get install libpcap-dev`
    * **On Fedora/CentOS/RHEL:** `sudo dnf install libpcap-devel`
    * **On macOS:** `brew install libpcap` (usually pre-installed)
    * **On Windows:** Download and install [Npcap](https://nmap.org/npcap/).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
    cd your-repo-name
    ```

2.  **Install the required Python libraries:**
    ```bash
    pip install scapy
    ```

## Usage

### 1. Find Your Network Interface

To find the name of your network interface (e.g., `eth0`, `wlan0`, `en0`), use one of the following commands:

* **Linux:** `ip a` or `ifconfig`
* **macOS:** `ifconfig`
* **Windows (PowerShell):** `Get-NetAdapter`

### 2. Run the Script

You must run the script with root or administrator privileges to capture network packets.

* **On Linux/macOS:**
    ```bash
    sudo python3 network_packet_detector.py
    ```
* **On Windows (PowerShell as Admin):**
    ```powershell
    python network_packet_detector.py
    ```

> **Note:** Make sure to update the `NETWORK_INTERFACE` variable in the script to match your interface name. The default is `en0`.

The script will start sniffing packets and print alerts to the console. Press `Ctrl+C` to stop the sniffer.

### 3. Customize Detection Logic

You can easily adjust the detection thresholds and patterns at the top of the script under the `--- Configuration ---` section to suit your network's needs.

* `SYN_FLOOD_THRESHOLD`
* `VERTICAL_SCAN_THRESHOLD_PORTS`
* `HORIZONTAL_SCAN_THRESHOLD_HOSTS`
* `SSH_BRUTE_FORCE_THRESHOLD`
* `MALICIOUS_PORTS`
* `SQL_INJECTION_PATTERNS`
* `XSS_PATTERNS`
* `PATH_TRAVERSAL_PATTERNS`

## Contributing

Contributions are welcome! If you have suggestions for new features, bug fixes, or improved detection patterns, please feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
