"""
Port Scanner with Output & Logging
Stage 4: Export results to JSON, CSV, TXT and automatic logging
"""

import socket
import sys
import argparse
import json
import csv
import os
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


def ensure_directories():
    """Create logs and reports directories if they don't exist."""
    os.makedirs('logs', exist_ok=True)
    os.makedirs('reports', exist_ok=True)


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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
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
                
                if state == 'open':
                    service = get_service_name(port)
                    print(f"[+] Port {port}: {state} ({service})")
                
                if not quiet and scanned_count % 50 == 0:
                    print(f"[*] Progress: {scanned_count}/{len(ports_to_scan)} ports scanned")
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(1)
    
    return results


def export_to_json(host, results, elapsed_time, ports_scanned, filename='logs/scan.json'):
    """
    Export scan results to JSON format.
    
    Args:
        host (str): Target hostname or IP
        results (dict): Scan results
        elapsed_time (float): Time taken for the scan
        ports_scanned (list): List of ports that were scanned
        filename (str): Output filename
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Format open ports with service names
    open_ports_detailed = [
        {'port': port, 'service': get_service_name(port)}
        for port in sorted(results['open'])
    ]
    
    data = {
        'scan_info': {
            'target': host,
            'timestamp': timestamp,
            'scan_time_seconds': round(elapsed_time, 2),
            'total_ports_scanned': len(ports_scanned),
        },
        'results': {
            'open': open_ports_detailed,
            'closed_count': len(results['closed']),
            'filtered_count': len(results['filtered']),
        },
        'summary': {
            'open_ports_found': len(results['open']),
            'closed_ports': len(results['closed']),
            'filtered_ports': len(results['filtered']),
        }
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"[✓] Results saved to: {filename}")


def export_to_csv(host, results, elapsed_time, filename='logs/scan.csv'):
    """
    Export scan results to CSV format.
    
    Args:
        host (str): Target hostname or IP
        results (dict): Scan results
        elapsed_time (float): Time taken for the scan
        filename (str): Output filename
    """
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow(['Port', 'Service', 'State'])
        
        # Open ports
        for port in sorted(results['open']):
            service = get_service_name(port)
            writer.writerow([port, service, 'open'])
        
        # Closed ports
        for port in sorted(results['closed']):
            service = get_service_name(port)
            writer.writerow([port, service, 'closed'])
        
        # Filtered ports
        for port in sorted(results['filtered']):
            service = get_service_name(port)
            writer.writerow([port, service, 'filtered'])
    
    print(f"[✓] Results saved to: {filename}")


def export_to_txt(host, results, elapsed_time, filename='logs/scan.txt'):
    """
    Export scan results to plain text format.
    
    Args:
        host (str): Target hostname or IP
        results (dict): Scan results
        elapsed_time (float): Time taken for the scan
        filename (str): Output filename
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    with open(filename, 'w') as f:
        f.write("="*70 + "\n")
        f.write("PORT SCANNER REPORT\n")
        f.write("="*70 + "\n\n")
        
        f.write(f"Target: {host}\n")
        f.write(f"Scan Date: {timestamp}\n")
        f.write(f"Scan Duration: {elapsed_time:.2f} seconds\n\n")
        
        f.write(f"OPEN PORTS ({len(results['open'])}):\n")
        f.write("-"*70 + "\n")
        if results['open']:
            for port in sorted(results['open']):
                service = get_service_name(port)
                f.write(f"  {port:5d} - {service}\n")
        else:
            f.write("  None\n")
        
        f.write(f"\nCLOSED PORTS ({len(results['closed'])}):\n")
        f.write("-"*70 + "\n")
        f.write(f"  {len(results['closed'])} ports closed (not listed)\n")
        
        f.write(f"\nFILTERED PORTS ({len(results['filtered'])}):\n")
        f.write("-"*70 + "\n")
        f.write(f"  {len(results['filtered'])} ports filtered (not listed)\n")
        
        f.write("\n" + "="*70 + "\n")
        f.write("END OF REPORT\n")
        f.write("="*70 + "\n")
    
    print(f"[✓] Results saved to: {filename}")


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
        if ',' in port_string:
            for part in port_string.split(','):
                if '-' in part:
                    start, end = part.split('-')
                    ports.extend(range(int(start), int(end) + 1))
                else:
                    ports.append(int(part))
        elif '-' in port_string:
            start, end = port_string.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(port_string))
        
        return sorted(list(set(ports)))
    
    except ValueError:
        print(f"[-] Invalid port format: {port_string}")
        print("    Examples: 80, 1-1000, 80,443,8080, 1-100,8000-9000")
        sys.exit(1)


def main():
    """Main entry point with output and logging features."""
    parser = argparse.ArgumentParser(
        description='Port Scanner with Output & Logging',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner_v4.py localhost
  python port_scanner_v4.py localhost --output scan.json
  python port_scanner_v4.py localhost --output scan.csv
  python port_scanner_v4.py localhost --output reports/scan.txt
  python port_scanner_v4.py example.com --top1000 --verbose
  python port_scanner_v4.py localhost --no-log
        """
    )
    
    parser.add_argument('host', help='Target hostname or IP address')
    
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('--ports', type=str, help='Custom port range (e.g., 1-1000)')
    port_group.add_argument('--top100', action='store_true', help='Scan top 100 ports (default)')
    port_group.add_argument('--top1000', action='store_true', help='Scan top 1000 ports')
    
    parser.add_argument('--timeout', type=int, default=1, help='Timeout per port (default: 1)')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    
    parser.add_argument('--output', type=str, help='Export results to file (e.g., scan.json, scan.csv, scan.txt)')
    parser.add_argument('--no-log', action='store_true', help='Do not auto-log to logs folder')
    
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress progress messages')
    
    args = parser.parse_args()
    
    # Create directories
    ensure_directories()
    
    # Determine ports to scan
    if args.ports:
        ports_to_scan = parse_port_range(args.ports)
    elif args.top1000:
        ports_to_scan = sorted(list(set(TOP_100_PORTS + list(range(1, 1001)))))
    else:
        ports_to_scan = TOP_100_PORTS
    
    # Validate arguments
    if args.threads < 1 or args.threads > 500:
        print("[-] Thread count must be between 1 and 500")
        sys.exit(1)
    
    if args.timeout < 1 or args.timeout > 10:
        print("[-] Timeout must be between 1 and 10 seconds")
        sys.exit(1)
    
    # Start scan
    start_time = datetime.now()
    
    results = scan_range(
        args.host, 
        ports_to_scan, 
        timeout=args.timeout, 
        max_threads=args.threads,
        verbose=args.verbose,
        quiet=args.quiet
    )
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # Print results
    print_results(args.host, results, elapsed, verbose=args.verbose)
    
    # Auto-logging to logs folder (unless --no-log is used)
    if not args.no_log:
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        log_filename = f"logs/scan_{timestamp}.json"
        export_to_json(args.host, results, elapsed, ports_to_scan, log_filename)
    
    # Export to user-specified file
    if args.output:
        # Determine format from file extension
        if args.output.endswith('.json'):
            export_to_json(args.host, results, elapsed, ports_to_scan, args.output)
        elif args.output.endswith('.csv'):
            export_to_csv(args.host, results, elapsed, args.output)
        elif args.output.endswith('.txt'):
            export_to_txt(args.host, results, elapsed, args.output)
        else:
            print("[-] Unknown format. Use .json, .csv, or .txt")


if __name__ == "__main__":
    main()
