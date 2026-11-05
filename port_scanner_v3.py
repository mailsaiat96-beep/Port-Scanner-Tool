"""
Enhanced Port Scanner Tool
Stage 3: Service detection, common ports, and improved CLI
"""

import socket
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# Database of common ports and their services
COMMON_PORTS = {
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTP-SSL',
    587: 'SMTP',
    993: 'IMAP-SSL',
    995: 'POP3-SSL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB',
    6379: 'Redis',
    135: 'RPC',
    139: 'NetBIOS',
    389: 'LDAP',
    636: 'LDAPS',
    1433: 'MSSQL',
}

# Top 100 most common ports
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 179, 199, 443, 445, 465,
    514, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    389, 636, 1521, 1433, 5432, 5900, 6379, 8080, 8443, 27017, 50000, 50070,
    9200, 9300, 11211, 27017, 27018, 27019, 27020, 28017, 28018, 28019, 28020,
    50000, 50070, 9000, 9001, 9002, 9003, 9200, 9300, 8161, 8888, 9090, 9091,
    10000, 15672, 25565, 25575, 25576, 8161, 8888, 9090, 9091, 10000, 15672,
    25565, 25575, 25576, 5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008,
    5009, 5010, 5011, 5012, 5013, 5014, 5015, 5016, 5017, 5018, 5019, 5020,
]


def get_service_name(port):
    """
    Get the service name for a port.
    
    Args:
        port (int): Port number
    
    Returns:
        str: Service name or "Unknown" if not in database
    """
    return COMMON_PORTS.get(port, "Unknown")


def scan_port(host, port, timeout=1, verbose=False):
    """
    Attempt to connect to a specific port on a host.
    
    Args:
        host (str): Target hostname or IP address
        port (int): Port number to scan
        timeout (int): Connection timeout in seconds
        verbose (bool): Print extra details
    
    Returns:
        tuple: (port, state) where state is 'open', 'closed', or 'filtered'
    """
    try:
        # Create a socket object (IPv4, TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set timeout
        sock.settimeout(timeout)
        
        # Try to connect to the port
        result = sock.connect_ex((host, port))
        
        # Close the socket
        sock.close()
        
        # Interpret the result
        if result == 0:
            return (port, 'open')
        else:
            return (port, 'closed')
    
    except socket.gaierror:
        print(f"\n[-] Hostname '{host}' could not be resolved.")
        sys.exit(1)
    except socket.error as e:
        if verbose:
            print(f"[-] Error scanning port {port}: {str(e)}")
        return (port, 'filtered')


def scan_range(host, ports_to_scan, timeout=1, max_threads=50, verbose=False, quiet=False):
    """
    Scan a range/list of ports on a target host using threading.
    
    Args:
        host (str): Target hostname or IP address
        ports_to_scan (list): List of port numbers to scan
        timeout (int): Connection timeout per port
        max_threads (int): Maximum number of concurrent threads
        verbose (bool): Print detailed output
        quiet (bool): Suppress progress messages
    
    Returns:
        dict: Results with 'open', 'closed', 'filtered' port lists
    """
    results = {'open': [], 'closed': [], 'filtered': []}
    
    if not quiet:
        print(f"\n[*] Scanning host: {host}")
        print(f"[*] Total ports to scan: {len(ports_to_scan)}")
        print(f"[*] Threads: {max_threads}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(scan_port, host, port, timeout, verbose): port 
                for port in ports_to_scan
            }
            
            scanned_count = 0
            for future in as_completed(futures):
                port, state = future.result()
                results[state].append(port)
                scanned_count += 1
                
                # Print open ports immediately
                if state == 'open':
                    service = get_service_name(port)
                    print(f"[+] Port {port}: {state} ({service})")
                
                # Print progress every 50 ports (unless quiet)
                if not quiet and scanned_count % 50 == 0:
                    print(f"[*] Progress: {scanned_count}/{len(ports_to_scan)} ports scanned")
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(1)
    
    return results


def print_results(host, results, elapsed_time, verbose=False):
    """
    Print the scan results in a formatted way.
    
    Args:
        host (str): Target hostname or IP
        results (dict): Results dictionary from scan_range()
        elapsed_time (float): Time taken for the scan
        verbose (bool): Print extra details
    """
    print("\n" + "="*70)
    print(f"SCAN RESULTS FOR {host}")
    print("="*70)
    
    print(f"\n[+] Open ports ({len(results['open'])}):")
    if results['open']:
        for port in sorted(results['open']):
            service = get_service_name(port)
            print(f"    {port:5d} - {service}")
    else:
        print("    None")
    
    if verbose:
        print(f"\n[-] Closed ports ({len(results['closed'])}):")
        if results['closed'] and len(results['closed']) <= 20:
            for port in sorted(results['closed'])[:20]:
                print(f"    {port}")
            if len(results['closed']) > 20:
                print(f"    ... and {len(results['closed']) - 20} more")
        else:
            print(f"    {len(results['closed'])} ports closed (not listed)")
        
        print(f"\n[?] Filtered ports ({len(results['filtered'])}):")
        if results['filtered'] and len(results['filtered']) <= 20:
            for port in sorted(results['filtered'])[:20]:
                print(f"    {port}")
            if len(results['filtered']) > 20:
                print(f"    ... and {len(results['filtered']) - 20} more")
        else:
            print(f"    {len(results['filtered'])} ports filtered (not listed)")
    else:
        print(f"\n[-] Closed ports: {len(results['closed'])} (not listed)")
        print(f"[?] Filtered ports: {len(results['filtered'])} (not listed)")
    
    print("\n" + "="*70)
    print(f"Scan completed in {elapsed_time:.2f} seconds")
    print("="*70 + "\n")


def parse_port_range(port_string):
    """
    Parse a port string like "1-1000" or "80,443,8080" into a list of ports.
    
    Args:
        port_string (str): Port range/list string
    
    Returns:
        list: List of port numbers
    """
    ports = []
    
    try:
        # Handle comma-separated ports
        if ',' in port_string:
            for part in port_string.split(','):
                if '-' in part:
                    start, end = part.split('-')
                    ports.extend(range(int(start), int(end) + 1))
                else:
                    ports.append(int(part))
        # Handle range
        elif '-' in port_string:
            start, end = port_string.split('-')
            ports.extend(range(int(start), int(end) + 1))
        # Single port
        else:
            ports.append(int(port_string))
        
        return sorted(list(set(ports)))  # Remove duplicates and sort
    
    except ValueError:
        print(f"[-] Invalid port format: {port_string}")
        print("    Examples: 80, 1-1000, 80,443,8080, 1-100,8000-9000")
        sys.exit(1)


def main():
    """Main entry point with improved argument parsing."""
    parser = argparse.ArgumentParser(
        description='Enhanced Port Scanner - Scan ports with service detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner_v3.py localhost
  python port_scanner_v3.py 192.168.1.1 --top1000
  python port_scanner_v3.py example.com --ports 1-10000
  python port_scanner_v3.py localhost --verbose --timeout 2
  python port_scanner_v3.py localhost --quiet --threads 100
        """
    )
    
    # Positional argument
    parser.add_argument('host', help='Target hostname or IP address')
    
    # Port options (mutually exclusive)
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('--ports', type=str, help='Custom port range (e.g., 1-1000 or 80,443,8080)')
    port_group.add_argument('--top100', action='store_true', help='Scan top 100 common ports (default)')
    port_group.add_argument('--top1000', action='store_true', help='Scan top 1000 common ports')
    
    # Scan options
    parser.add_argument('--timeout', type=int, default=1, help='Timeout per port in seconds (default: 1)')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    
    # Output options
    parser.add_argument('--verbose', '-v', action='store_true', help='Show all port details')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress progress messages')
    
    args = parser.parse_args()
    
    # Determine which ports to scan
    if args.ports:
        ports_to_scan = parse_port_range(args.ports)
    elif args.top1000:
        # Get top 1000 by expanding the top 100 list
        ports_to_scan = sorted(list(set(TOP_100_PORTS + list(range(1, 1001)))))
    else:
        # Default: top 100
        ports_to_scan = TOP_100_PORTS
    
    # Validate thread count
    if args.threads < 1 or args.threads > 500:
        print("[-] Thread count must be between 1 and 500")
        sys.exit(1)
    
    # Validate timeout
    if args.timeout < 1 or args.timeout > 10:
        print("[-] Timeout must be between 1 and 10 seconds")
        sys.exit(1)
    
    # Start timer
    start_time = datetime.now()
    
    # Run the scan
    results = scan_range(
        args.host, 
        ports_to_scan, 
        timeout=args.timeout, 
        max_threads=args.threads,
        verbose=args.verbose,
        quiet=args.quiet
    )
    
    # Calculate elapsed time
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # Print results
    print_results(args.host, results, elapsed, verbose=args.verbose)


if __name__ == "__main__":
    main()
