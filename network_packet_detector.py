# Note: Change the interface accordingly to your OS and system, in the main function.

import logging
from scapy.all import sniff, IP, TCP, UDP, Raw
import time
from collections import defaultdict, deque
import re

# --- Configuration ---
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define potentially malicious ports (expanded list)
# This list includes common services, backdoor ports, and ports often targeted in exploits.
MALICIOUS_PORTS = {
    7: "ECHO (can be used in DoS amplification)",
    21: "FTP (often targeted for brute-force/anon access)",
    22: "SSH (Secure Shell, often targeted for brute-force attacks)",
    23: "Telnet (unencrypted, highly vulnerable to eavesdropping/brute-force)",
    25: "SMTP (email, can be used for spam/phishing)",
    53: "DNS (can be used for DoS amplification, tunneling)",
    80: "HTTP (web, target for web exploits, botnet C2)",
    111: "Portmapper/RPCBind (vulnerable to DDoS amplification, info disclosure)",
    135: "Microsoft RPC (often exploited, e.g., Conficker)",
    137: "NetBIOS Name Service (info disclosure, exploitation)",
    138: "NetBIOS Datagram Service (info disclosure, exploitation)",
    139: "NetBIOS Session Service (info disclosure, exploitation)",
    443: "HTTPS (encrypted web, still target for exploits, phishing)",
    445: "Microsoft-DS (SMB/CIFS, often exploited, e.g., EternalBlue/WannaCry)",
    500: "ISAKMP (Internet Security Association and Key Management Protocol, VPN attacks)",
    513: "Login/Rexec (legacy, often vulnerable)",
    514: "Shell/Rsh (legacy, often vulnerable)",
    666: "Doom/IRC (historical malware/backdoor port)",
    1433: "MSSQL (Microsoft SQL Server, often targeted for brute-force)",
    1434: "MSSQL Monitor (vulnerable to DoS, info disclosure)",
    1723: "PPTP (Point-to-Point Tunneling Protocol, known vulnerabilities)",
    3306: "MySQL (database, often targeted for brute-force)",
    3389: "RDP (Remote Desktop Protocol, prime target for brute force attacks)",
    5432: "PostgreSQL (database, often targeted)",
    5900: "VNC (Remote Desktop, often exposed without strong auth)",
    8080: "HTTP Proxy/Alt-HTTP (common for web apps, often less secured than 80/443)",
    9000: "Possible backdoor/management port",
    10000: "Webmin (common admin panel, often targeted)",
    27017: "MongoDB (default, often exposed without auth)",
    2222: "Alternative SSH port, often used by attackers to evade basic scans",
    # Specific known malware ports or common C2 (Command and Control) ports:
    689: "DCC (Direct Client-to-Client - often malware related)",
    1600: "KaZaA (P2P, sometimes associated with malware)",
    3127: "MyDoom (worm)",
    3410: "Back Orifice 2000 (RAT)",
    65535: "Max TCP port, sometimes used in scans",
    # Add more as research uncovers new threats
}

# Threshold for SYN flood detection
SYN_FLOOD_THRESHOLD = 15 # Increased threshold slightly
SYN_FLOOD_WINDOW_SECONDS = 5

# Thresholds for Port Scan Detection
VERTICAL_SCAN_THRESHOLD_PORTS = 10 # Number of distinct ports hit on one destination
VERTICAL_SCAN_WINDOW_SECONDS = 10
HORIZONTAL_SCAN_THRESHOLD_HOSTS = 5 # Number of distinct destination IPs hit from one source
HORIZONTAL_SCAN_WINDOW_SECONDS = 10

# Threshold for SSH Brute-Force Detection (simple connection attempt counter)
SSH_BRUTE_FORCE_THRESHOLD = 5 # Number of connection attempts to port 22
SSH_BRUTE_FORCE_WINDOW_SECONDS = 30

# --- Global State for Detection Logic ---
# To track SYN packets for flood detection: { 'source_ip': deque([(timestamp, count), ...]) }
syn_tracker = defaultdict(lambda: deque(maxlen=SYN_FLOOD_THRESHOLD * 2)) # Deque to efficiently manage window

# To track vertical scans: { 'src_ip': {'dst_ip': {'ports': set(), 'timestamps': deque()}} }
vertical_scan_tracker = defaultdict(lambda: defaultdict(lambda: {'ports': set(), 'timestamps': deque(maxlen=VERTICAL_SCAN_THRESHOLD_PORTS * 2)}))

# To track horizontal scans: { 'src_ip': {'dst_ips': set(), 'timestamps': deque()} }
horizontal_scan_tracker = defaultdict(lambda: {'dst_ips': set(), 'timestamps': deque(maxlen=HORIZONTAL_SCAN_THRESHOLD_HOSTS * 2)})

# To track SSH brute-force attempts: { 'src_ip': deque([timestamp, ...]) }
ssh_brute_force_tracker = defaultdict(lambda: deque(maxlen=SSH_BRUTE_FORCE_THRESHOLD * 2))

# --- Regular Expressions for HTTP Payload Analysis ---
# These are improved patterns for common web attacks.
# They are designed to be more robust against simple obfuscation.

# Note on '.*?' (non-greedy): This matches as few characters as possible.
# This can be more efficient than '.*' (greedy) and prevents it from
# matching too much of the payload, which could lead to missed detections.

SQL_INJECTION_PATTERNS = [
    # Classic 'OR 1=1' and similar logical statement attacks
    re.compile(r"\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),
    # Detects the classic UNION SELECT statement
    re.compile(r"\bUNION\b\s+SELECT\b", re.IGNORECASE),
    # Detects stacked queries (e.g., in MSSQL)
    re.compile(r";\s*(?:SELECT|UPDATE|INSERT|DELETE)\b", re.IGNORECASE),
    # Detects a common command execution stored procedure in MSSQL
    re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
    # Detects time-based blind injection (for MSSQL)
    re.compile(r"\bwaitfor\s+delay\s+['\"]?\d", re.IGNORECASE),
    # Detects common error-based injection functions (for MySQL/MariaDB)
    re.compile(r"\b(extractvalue|updatexml|floor)\s*\(\s*\(?", re.IGNORECASE),
    # Detects comments used to terminate a query
    re.compile(r"--\s*|#\s*", re.IGNORECASE),
]

XSS_PATTERNS = [
    # Detects common script tags, including variations
    re.compile(r"<script[\s>]|<img\s+src=[\"\']?x\s+onerror=|document\.cookie", re.IGNORECASE),
    # Detects classic event handlers (can be used on any HTML tag)
    re.compile(r"on(load|error|mouseover|click|submit|focus|key)", re.IGNORECASE),
    # Detects the javascript: pseudo-protocol (e.g., in a link href)
    re.compile(r"javascript\s*:", re.IGNORECASE),
    # Detects eval() function for code execution
    re.compile(r"eval\s*\(", re.IGNORECASE),
    # Detects common function calls used in XSS
    re.compile(r"(?:alert|prompt|confirm|document\.write)\s*\(", re.IGNORECASE),
    # Detects the use of `>` and `<` which are often encoded to bypass filters
    re.compile(r"<\s*!DOCTYPE", re.IGNORECASE), # Basic check for HTML structure
]

PATH_TRAVERSAL_PATTERNS = [
    # Detects the classic '..' and '/' combination
    re.compile(r"(\.\.\/)", re.IGNORECASE),
    # Detects the Windows-style '..' and '\' combination
    re.compile(r"(\.\.\\)", re.IGNORECASE),
    # Detects common URL-encoded variations
    re.compile(r"(%2e%2e%2f|%2e%2e\\)", re.IGNORECASE),
    # Detects doubly-encoded variations (e.g., %252e%252e%252f)
    re.compile(r"(%252e%252e%252f|%252e%252e\\)", re.IGNORECASE),
    # Detects attempts to access common sensitive files (Linux/Unix)
    re.compile(r"(etc/passwd|etc/shadow|proc/self/cwd)", re.IGNORECASE),
    # Detects attempts to access common sensitive files (Windows)
    re.compile(r"(boot\.ini|windows/system32/drivers/etc/hosts)", re.IGNORECASE),
]
# --- Helper Functions for Detection ---
def _check_syn_flood(src_ip, current_time):
    """Checks for SYN flood based on a sliding window."""
    syn_tracker[src_ip].append(current_time)

    # Remove timestamps older than the window
    while syn_tracker[src_ip] and current_time - syn_tracker[src_ip][0] > SYN_FLOOD_WINDOW_SECONDS:
        syn_tracker[src_ip].popleft()

    if len(syn_tracker[src_ip]) >= SYN_FLOOD_THRESHOLD:
        logging.critical(
            f"SYN FLOOD DETECTED: {src_ip} sending too many SYNs "
            f"({len(syn_tracker[src_ip])} in {SYN_FLOOD_WINDOW_SECONDS}s)"
        )
        return True
    return False

def _check_vertical_scan(src_ip, dst_ip, dst_port, current_time):
    """Checks for vertical port scan (single source, single dest, many ports)."""
    tracker = vertical_scan_tracker[src_ip][dst_ip]
    tracker['ports'].add(dst_port)
    tracker['timestamps'].append(current_time)

    # Remove timestamps older than the window
    while tracker['timestamps'] and current_time - tracker['timestamps'][0] > VERTICAL_SCAN_WINDOW_SECONDS:
        tracker['timestamps'].popleft()

    if len(tracker['ports']) >= VERTICAL_SCAN_THRESHOLD_PORTS:
        logging.warning(
            f"VERTICAL PORT SCAN DETECTED: {src_ip} scanning {dst_ip} on "
            f"{len(tracker['ports'])} distinct ports in {VERTICAL_SCAN_WINDOW_SECONDS}s. "
            f"Ports: {sorted(list(tracker['ports']))}"
        )
        # Reset the tracker for this specific src-dst pair to avoid continuous alerts
        vertical_scan_tracker[src_ip][dst_ip] = {'ports': set(), 'timestamps': deque()}
        return True
    return False

def _check_horizontal_scan(src_ip, dst_ip, current_time):
    """Checks for horizontal port scan (single source, many destinations)."""
    tracker = horizontal_scan_tracker[src_ip]
    tracker['dst_ips'].add(dst_ip)
    tracker['timestamps'].append(current_time)

    # Remove timestamps older than the window
    while tracker['timestamps'] and current_time - tracker['timestamps'][0] > HORIZONTAL_SCAN_WINDOW_SECONDS:
        tracker['timestamps'].popleft()

    if len(tracker['dst_ips']) >= HORIZONTAL_SCAN_THRESHOLD_HOSTS:
        logging.warning(
            f"HORIZONTAL PORT SCAN DETECTED: {src_ip} scanning {len(tracker['dst_ips'])} "
            f"distinct hosts in {HORIZONTAL_SCAN_WINDOW_SECONDS}s. Hosts: {sorted(list(tracker['dst_ips']))}"
        )
        # Reset the tracker for this source to avoid continuous alerts
        horizontal_scan_tracker[src_ip] = {'dst_ips': set(), 'timestamps': deque()}
        return True
    return False

def _check_ssh_brute_force(src_ip, current_time):
    """Checks for multiple connection attempts to SSH (port 22)."""
    ssh_brute_force_tracker[src_ip].append(current_time)

    # Remove timestamps older than the window
    while ssh_brute_force_tracker[src_ip] and current_time - ssh_brute_force_tracker[src_ip][0] > SSH_BRUTE_FORCE_WINDOW_SECONDS:
        ssh_brute_force_tracker[src_ip].popleft()

    if len(ssh_brute_force_tracker[src_ip]) >= SSH_BRUTE_FORCE_THRESHOLD:
        logging.critical(
            f"SSH BRUTE-FORCE ATTEMPT DETECTED: {src_ip} attempted to connect to SSH "
            f"{len(ssh_brute_force_tracker[src_ip])} times in {SSH_BRUTE_FORCE_WINDOW_SECONDS}s."
        )
        # Optionally, clear the tracker for this IP
        # ssh_brute_force_tracker[src_ip] = deque()
        return True
    return False

def _check_http_payload_for_attacks(payload, src_ip, dst_ip, dst_port):
    """Checks HTTP payload for common web attack patterns."""
    if not payload:
        return False

    # SQL Injection detection
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(payload):
            logging.critical(
                f"SQL INJECTION ATTEMPT DETECTED: {src_ip} -> {dst_ip}:{dst_port}. Payload: '{payload[:100]}...'"
            )
            return True

    # XSS detection
    for pattern in XSS_PATTERNS:
        if pattern.search(payload):
            logging.critical(
                f"XSS ATTEMPT DETECTED: {src_ip} -> {dst_ip}:{dst_port}. Payload: '{payload[:100]}...'"
            )
            return True

    # Path Traversal detection
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(payload):
            logging.critical(
                f"PATH TRAVERSAL ATTEMPT DETECTED: {src_ip} -> {dst_ip}:{dst_port}. Payload: '{payload[:100]}...'"
            )
            return True
    return False

# --- Packet Analysis Function ---
def analyze_packet(packet):
    """
    Analyzes a single captured packet for suspicious patterns.
    """
    current_time = time.time()
    try:
        # Check if the packet has an IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto  # IP protocol number (e.g., 6 for TCP, 17 for UDP)

            logging.debug(f"Packet from {src_ip} to {dst_ip}, Protocol: {protocol}")

            # --- Malformed Packet Detection (Basic) ---
            # Check if IP total length matches actual packet length (simple check)
            if packet[IP].len != len(packet[IP]):
                logging.warning(f"MALFORMED IP PACKET: IP length mismatch from {src_ip} to {dst_ip}")

            # --- TCP Protocol Analysis ---
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags  # TCP flags (e.g., S for SYN, A for ACK, F for FIN)

                logging.debug(f"  TCP - Src Port: {src_port}, Dst Port: {dst_port}, Flags: {flags}")

                # 1. Detect unusual/malicious ports
                if dst_port in MALICIOUS_PORTS:
                    logging.warning(
                        f"MALICIOUS PORT ALERT: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                        f"(Potential: {MALICIOUS_PORTS[dst_port]})"
                    )
                if src_port in MALICIOUS_PORTS and src_port not in [20, 80, 443]: # Exclude common server source ports
                    logging.warning(
                        f"MALICIOUS PORT ALERT: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                        f"(Source Port Potential: {MALICIOUS_PORTS[src_port]})"
                    )

                # Check for TCP Data Offset anomaly (minimum is 5, max is 15)
                if packet[TCP].dataofs < 5 or packet[TCP].dataofs > 15:
                    logging.warning(f"MALFORMED TCP PACKET: Invalid data offset from {src_ip} to {dst_ip}:{dst_port}")

                # 2. Basic SYN Flood Detection
                if 'S' in str(flags):  # Check for SYN flag
                    _check_syn_flood(src_ip, current_time)

                # 3. Check for specific TCP flags patterns (e.g., Xmas tree scan, Null scan)
                # Scapy's flags can be a string like 'S' for SYN, 'SA' for SYN-ACK etc.
                if str(flags) == 'FPUARS': # All flags set (Xmas Tree)
                    logging.warning(f"XMAS TREE SCAN DETECTED from {src_ip} to {dst_ip}:{dst_port}")
                elif str(flags) == '': # No flags set (Null Scan)
                    logging.warning(f"NULL SCAN DETECTED from {src_ip} to {dst_ip}:{dst_port}")
                elif str(flags) == 'FPU': # FIN, PSH, URG - Common in some stealth scans
                    logging.warning(f"FIN/PSH/URG SCAN DETECTED from {src_ip} to {dst_ip}:{dst_port}")

                # 4. Port Scan Detection
                if 'S' in str(flags) or 'A' in str(flags) or 'F' in str(flags) or 'R' in str(flags):
                    # Only consider connection attempts/resets for scan detection
                    _check_vertical_scan(src_ip, dst_ip, dst_port, current_time)
                    _check_horizontal_scan(src_ip, dst_ip, current_time)

                # 5. SSH Brute-Force (Port 22 attempts)
                if dst_port == 22 and 'S' in str(flags): # New connection attempt to SSH
                    _check_ssh_brute_force(src_ip, current_time)

                # 6. Check for HTTP payload content (more sophisticated string/regex search)
                if (dst_port == 80 or dst_port == 443 or dst_port == 8080) and Raw in packet:
                    try:
                        # Try to decode as UTF-8, but handle errors gracefully
                        payload = packet[Raw].load.decode('utf-8', errors='replace')
                        _check_http_payload_for_attacks(payload, src_ip, dst_ip, dst_port)
                    except Exception as e:
                        # If decoding fails completely, try with latin-1 or just skip
                        try:
                            payload = packet[Raw].load.decode('latin-1', errors='replace')
                            _check_http_payload_for_attacks(payload, src_ip, dst_ip, dst_port)
                        except Exception:
                            logging.debug(f"Could not decode payload from {src_ip}:{src_port} - skipping payload analysis")

            # --- UDP Protocol Analysis ---
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                logging.debug(f"  UDP - Src Port: {src_port}, Dst Port: {dst_port}")

                # Detect unusual/malicious UDP ports
                if dst_port in MALICIOUS_PORTS:
                    logging.warning(
                        f"MALICIOUS UDP PORT ALERT: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                        f"(Potential: {MALICIOUS_PORTS[dst_port]})"
                    )
                if src_port in MALICIOUS_PORTS and src_port != 53: # Exclude common DNS source port
                    logging.warning(
                        f"MALICIOUS UDP PORT ALERT: {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                        f"(Source Port Potential: {MALICIOUS_PORTS[src_port]})"
                    )

                # Simple DNS tunneling heuristic: unusually long DNS queries
                if dst_port == 53 and hasattr(packet, 'qd') and packet.qd: # Check for DNS query layer
                    try:
                        qname = packet.qd.qname.decode('utf-8', errors='replace').strip('.')
                        if len(qname) > 50 and '.' in qname: # Heuristic: long domain name with dots
                            logging.warning(f"POTENTIAL DNS TUNNELING: Unusually long DNS query from {src_ip}: {qname}")
                    except Exception:
                        logging.debug(f"Could not process DNS query from {src_ip}")

            # --- Other IP Protocols (e.g., ICMP) ---
            elif protocol == 1:  # ICMP
                # You could add ICMP specific checks here, like large pings,
                # or unusual ICMP types/codes.
                logging.debug(f"  ICMP packet from {src_ip} to {dst_ip}")
                # Check for large ICMP packets (potential Smurf attack, though less common now)
                if len(packet) > 1500: # Typical MTU, larger might indicate flood
                    logging.warning(f"LARGE ICMP PACKET DETECTED: {len(packet)} bytes from {src_ip} to {dst_ip}")

        else:
            logging.debug("Non-IP packet captured.")

    except Exception as e:
        logging.error(f"Error processing packet: {e}", exc_info=True)


# --- Main Sniffing Function ---
def start_sniffer(interface="en0", count=0):
    """
    Starts the packet sniffer.

    Args:
        interface (str): The network interface to sniff on (e.g., "eth0", "wlan0").
                         On Windows, it might look like "\\Device\\NPF_{GUID}" or your adapter name.
                         You might need to list available interfaces first using `scapy.all.get_if_list()`.
        count (int): Number of packets to sniff. 0 means sniff indefinitely.
    """
    logging.info(f"Starting packet sniffer on interface: {interface}...")
    logging.info("Press Ctrl+C to stop.")
    try:
        # filter: "tcp" for only TCP packets, "udp" for UDP, "icmp" for ICMP.
        # Can combine: "tcp or udp"
        # Or filter by host: "host 192.168.1.1"
        # Or by port: "port 80"
        # Using no filter to capture all IP packets for comprehensive analysis
        sniff(iface=interface, prn=analyze_packet, store=0, count=count)
    except KeyboardInterrupt:
        logging.info("Sniffer stopped by user.")
    except Exception as e:
        logging.critical(f"Failed to start sniffer: {e}. "
                         f"Ensure you have sufficient permissions (e.g., run as root/administrator) "
                         f"and the interface '{interface}' is correct.")
        logging.info("Available interfaces (run `scapy.all.get_if_list()` in an interpreter if unsure):")
        # This part won't execute if scapy.all is not imported correctly or iface is wrong
        # Consider printing get_if_list() results here if it helps with debugging interface issues
        # from scapy.all import get_if_list
        # print(get_if_list())

# --- Entry Point ---
if __name__ == "__main__":
    # IMPORTANT: Replace 'en0' with your actual network interface name.
    # On Linux, use `ip a` or `ifconfig` to find it (e.g., 'eth0', 'wlan0').
    # On macOS, use `ifconfig` (e.g., 'en0', 'en1').
    # On Windows, use `ipconfig` or `get-netadapter` in PowerShell,
    # or list them with scapy in a Python shell: `from scapy.all import show_interfaces; show_interfaces()`.
    # You will likely need to run this script with administrator/root privileges
    # (`sudo python3 network_packet_detector.py`) to capture packets.
    NETWORK_INTERFACE = "eth0" # Change the interface accordingly.

    # To run indefinitely: count=0
    # To run for a specific number of packets: count=100
    start_sniffer(interface=NETWORK_INTERFACE, count=0)
