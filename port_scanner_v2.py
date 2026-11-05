"""
Multi-Threaded Port Scanner Tool
Stage 2: Using threading for parallel scanning
"""

import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host, port, timeout=1):
    """
    Attempt to connect to a specific port on a host.
    
    Args:
        host (str): Target hostname or IP address
        port (int): Port number to scan
        timeout (int): Connection timeout in seconds
    
    Returns:
        tuple: (port, state) where state is 'open', 'closed', or 'filtered'
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
            return (port, 'open')
        else:
            return (port, 'closed')
    
    except socket.gaierror:
        # Hostname could not be resolved
        print(f"\n[-] Hostname '{host}' could not be resolved.")
        sys.exit(1)
    except socket.error:
        # Connection failed (likely filtered)
        return (port, 'filtered')


def scan_range(host, port_range, timeout=1, max_threads=50):
    """
    Scan a range of ports on a target host using threading.
    
    Args:
        host (str): Target hostname or IP address
        port_range (tuple): (start_port, end_port) inclusive
        timeout (int): Connection timeout per port
        max_threads (int): Maximum number of concurrent threads
    
    Returns:
        dict: Results with 'open', 'closed', 'filtered' port lists
    """
    start_port, end_port = port_range
    results = {'open': [], 'closed': [], 'filtered': []}
    
    print(f"\n[*] Scanning host: {host}")
    print(f"[*] Port range: {start_port}-{end_port}")
    print(f"[*] Threads: {max_threads}")
    print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    try:
        # Create a thread pool executor
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all port scanning tasks to the thread pool
            futures = {
                executor.submit(scan_port, host, port, timeout): port 
                for port in range(start_port, end_port + 1)
            }
            
            # Process results as they complete
            scanned_count = 0
            for future in as_completed(futures):
                port, state = future.result()
                results[state].append(port)
                scanned_count += 1
                
                # Print open ports immediately
                if state == 'open':
                    print(f"[+] Port {port}: {state}")
                
                # Print progress every 50 ports
                if scanned_count % 50 == 0:
                    print(f"[*] Progress: {scanned_count}/{end_port - start_port + 1} ports scanned")
    
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
        print("Usage: python port_scanner_v2.py <host> [start_port] [end_port] [threads]")
        print("\nExamples:")
        print("  python port_scanner_v2.py example.com")
        print("  python port_scanner_v2.py 192.168.1.1 1 100")
        print("  python port_scanner_v2.py localhost 20 443 50")
        sys.exit(1)
    
    host = sys.argv[1]
    
    # Default port range (common ports)
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end_port = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
    max_threads = int(sys.argv[4]) if len(sys.argv) > 4 else 50
    
    # Start timer
    start_time = datetime.now()
    
    # Run the scan
    results = scan_range(host, (start_port, end_port), timeout=1, max_threads=max_threads)
    
    # Calculate elapsed time
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # Print results
    print_results(host, results, elapsed)


if __name__ == "__main__":
    main()