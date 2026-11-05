"""
Simple Port Scanner Tool
Stage 1: Core scanning logic with single-threaded TCP scanning
"""

import socket
import sys
from datetime import datetime


def scan_port(host, port, timeout=1):
    """
    Attempt to connect to a specific port on a host.
    
    Args:
        host (str): Target hostname or IP address
        port (int): Port number to scan
        timeout (int): Connection timeout in seconds
    
    Returns:
        str: 'open', 'closed', or 'filtered'
    """
    try:
        # Create a socket object (IPv4, TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set timeout so we don't wait forever for filtered ports
        sock.settimeout(timeout)
        
        # Try to connect to the port
        result = sock.connect_ex((host, port))
        
        # Close the socket
        sock.close()
        
        # Interpret the result
        if result == 0:
            return 'open'
        else:
            return 'closed'
    
    except socket.gaierror:
        # Hostname could not be resolved
        print(f"\n[-] Hostname '{host}' could not be resolved.")
        sys.exit(1)
    except socket.error:
        # Connection failed (likely filtered)
        return 'filtered'


def scan_range(host, port_range, timeout=1):
    """
    Scan a range of ports on a target host.
    
    Args:
        host (str): Target hostname or IP address
        port_range (tuple): (start_port, end_port) inclusive
        timeout (int): Connection timeout per port
    
    Returns:
        dict: Results with 'open', 'closed', 'filtered' port lists
    """
    start_port, end_port = port_range
    results = {'open': [], 'closed': [], 'filtered': []}
    
    print(f"\n[*] Scanning host: {host}")
    print(f"[*] Port range: {start_port}-{end_port}")
    print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    try:
        for port in range(start_port, end_port + 1):
            state = scan_port(host, port, timeout)
            results[state].append(port)
            
            # Simple progress indicator
            if state == 'open':
                print(f"[+] Port {port}: {state}")
            elif port % 100 == 0:  # Print progress every 100 ports
                print(f"[*] Progress: scanned up to port {port}")
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(1)
    
    return results


def print_results(host, results, elapsed_time):
    """
    Print the scan results in a formatted way.
    
    Args:
        host (str): Target hostname or IP
        results (dict): Results dictionary from scan_range()
        elapsed_time (float): Time taken for the scan
    """
    print("\n" + "="*60)
    print(f"SCAN RESULTS FOR {host}")
    print("="*60)
    
    print(f"\n[+] Open ports ({len(results['open'])}):")
    if results['open']:
        for port in sorted(results['open']):
            print(f"    {port}")
    else:
        print("    None")
    
    print(f"\n[-] Closed ports ({len(results['closed'])}):")
    if results['closed'] and len(results['closed']) <= 10:
        # Only show closed if there aren't too many
        for port in sorted(results['closed'])[:10]:
            print(f"    {port}")
        if len(results['closed']) > 10:
            print(f"    ... and {len(results['closed']) - 10} more")
    else:
        print(f"    {len(results['closed'])} ports closed (not listed)")
    
    print(f"\n[?] Filtered ports ({len(results['filtered'])}):")
    if results['filtered'] and len(results['filtered']) <= 10:
        for port in sorted(results['filtered'])[:10]:
            print(f"    {port}")
        if len(results['filtered']) > 10:
            print(f"    ... and {len(results['filtered']) - 10} more")
    else:
        print(f"    {len(results['filtered'])} ports filtered (not listed)")
    
    print("\n" + "="*60)
    print(f"Scan completed in {elapsed_time:.2f} seconds")
    print("="*60 + "\n")


def main():
    """Main entry point for the port scanner."""
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <host> [start_port] [end_port]")
        print("\nExamples:")
        print("  python port_scanner.py example.com")
        print("  python port_scanner.py 192.168.1.1 1 100")
        print("  python port_scanner.py localhost 20 443")
        sys.exit(1)
    
    host = sys.argv[1]
    
    # Default port range (common ports)
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    
    # Start timer
    start_time = datetime.now()
    
    # Run the scan
    results = scan_range(host, (start_port, end_port), timeout=1)
    
    # Calculate elapsed time
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # Print results
    print_results(host, results, elapsed)


if __name__ == "__main__":
    main()
