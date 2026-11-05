# Python Port Scanner

A multi-threaded TCP port scanner built from scratch in Python using the standard `socket` library. It scans a target host, reports open, closed, and filtered ports, identifies common services by port number, and exports results to JSON, CSV, or TXT.

> **Use responsibly:** Only scan systems you own or have explicit permission to test.

## Features

- TCP connect scanning with `socket.connect_ex()`
- Multi-threaded scanning with `ThreadPoolExecutor` and a configurable thread count
- Service identification for common ports, including HTTP, SSH, SMB, RDP, and MySQL
- Default scan of the top 100 common ports, with support for custom ranges and port lists
- Export results to JSON, CSV, or TXT
- Automatic timestamped logging of scans to `logs/`
- Command-line interface built with `argparse`
- Standard-library-only implementation; no third-party dependencies

## Requirements

- Python 3.9 or higher
- Windows, Linux, or macOS

No third-party packages are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/Port-Scanner-Tool.git
cd Port-Scanner-Tool
```

Optionally, create and activate a virtual environment.

**Windows:**

```bash
python -m venv venv
venv\\Scripts\\activate
```

**Linux / macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

No `pip install` command is needed because the project uses Python's standard library.

## Usage

Run the default scan of the top 100 common ports:

```bash
python port_scanner_v4.py localhost
```

Scan the top 1000 ports:

```bash
python port_scanner_v4.py localhost --top1000
```

Scan a custom port range:

```bash
python port_scanner_v4.py 192.168.1.10 --ports 1-1000
```

Scan specific ports:

```bash
python port_scanner_v4.py localhost --ports 22,80,443,3306
```

Export results to a file. The output format is selected from the file extension:

```bash
python port_scanner_v4.py localhost --output reports/scan.json
python port_scanner_v4.py localhost --output reports/scan.csv
python port_scanner_v4.py localhost --output reports/scan.txt
```

Display help:

```bash
python port_scanner_v4.py --help
```

### Command-line options

| Option | Description | Default |
|---|---|---|
| `host` | Target hostname or IP address (required) | — |
| `--ports` | Port range or list, e.g. `1-1000` or `80,443,8080` | — |
| `--top100` | Scan the top 100 common ports | Default |
| `--top1000` | Scan the top 1000 common ports | — |
| `--threads` | Number of concurrent threads (1–500) | `50` |
| `--timeout` | Connection timeout per port in seconds (1–10) | `1` |
| `--output` | Export file; supported extensions are `.json`, `.csv`, and `.txt` | — |
| `--no-log` | Disable automatic logging to `logs/` | Off |
| `--verbose`, `-v` | Show closed and filtered port details | Off |
| `--quiet`, `-q` | Suppress progress messages | Off |

`--ports`, `--top100`, and `--top1000` cannot be used together.

## Example output

The following is an illustrative example. Actual results depend on the target and network conditions.

```text
[*] Scanning host: localhost
[*] Total ports to scan: 99
[*] Threads: 50
[*] Timeout: 1s
[*] Starting scan at 2026-07-01 20:25:14

[+] Port 135: open (RPC)
[+] Port 445: open (SMB)

======================================================================
SCAN RESULTS FOR localhost
======================================================================

[+] Open ports (2):
      135 - RPC
      445 - SMB

[-] Closed ports: 97 (not listed)
[?] Filtered ports: 0 (not listed)

======================================================================
Scan completed in 2.05 seconds
======================================================================

[OK] Results saved to: logs/scan_2026-07-01_20-25-16.json
```

### Example JSON export

```json
{
  "scan_info": {
    "target": "localhost",
    "timestamp": "2026-07-01 20:25:16",
    "scan_time_seconds": 2.05,
    "total_ports_scanned": 99
  },
  "results": {
    "open": [
      {"port": 135, "service": "RPC"},
      {"port": 445, "service": "SMB"}
    ],
    "closed_count": 97,
    "filtered_count": 0
  },
  "summary": {
    "open_ports_found": 2,
    "closed_ports": 97,
    "filtered_ports": 0
  }
}
```

## How it works

1. **Input parsing:** `argparse` reads the target and command-line options. The port arguments are converted into a sorted list of port numbers.
2. **TCP connection attempts:** The scanner tests each selected port using `socket.connect_ex()`.
   - A return value of `0` indicates that the TCP connection succeeded and the port is open.
   - A connection-refused result generally indicates a closed port.
   - Timeouts and certain network errors may indicate that a port is filtered or unreachable. The exact interpretation depends on the operating system and network conditions.
3. **Concurrency:** `ThreadPoolExecutor` runs multiple port checks concurrently. `as_completed()` processes each result as it finishes.
4. **Service lookup:** Open ports are matched against a built-in dictionary of common port-to-service names.
5. **Output:** Results are displayed in the terminal, automatically logged to `logs/`, and optionally exported to the file specified by `--output`.

## Performance

Measurements reported for localhost on Windows 10/11. Results will vary depending on the machine, operating system, and network conditions.

| Version | Method | Ports scanned | Time |
|---|---|---:|---:|
| v1 | Sequential | 424 (ports 20–443) | 424.42 s |
| v2 | 50 threads | 424 (ports 20–443) | 9.11 s |
| v4 | 50 threads, top 100 ports | 99 | 2.05 s |

In these tests, using multiple threads substantially reduced scan time. Each connection attempt can spend time waiting for a network response, so concurrent attempts can reduce the overall duration. These figures are observations from the stated test environment, not guaranteed performance benchmarks.

## Project structure

The following structure reflects the versions and folders described for this project. Keep it aligned with the files actually present in your repository.

```text
Port-Scanner-Tool/
├── port_scanner_v1.py    # Stage 1: sequential scanner
├── port_scanner_v2.py    # Stage 2: multi-threaded scanner
├── port_scanner_v3.py    # Stage 3: service detection and CLI options
├── port_scanner_v4.py    # Stage 4: output, export, and logging (final version)
├── logs/                 # Automatically generated scan logs
├── reports/              # Exported results, created when --output is used
└── README.md
```

The earlier versions (v1 to v3) are retained to show the project's development. `port_scanner_v4.py` is the complete version described in this documentation.

Generated logs and reports are excluded from version control where configured in `.gitignore`.

## Limitations

- **TCP only:** UDP scanning is not implemented.
- **Basic filtered-port classification:** Socket errors are grouped into broad outcomes. The scanner does not distinguish every possible firewall response or network condition.
- **Static service names:** Services are identified using a fixed port-to-name table. The scanner does not detect service versions or read service banners.
- **No operating-system detection:** The scanner does not perform OS fingerprinting.
- **IPv4 only:** The scanner uses `AF_INET`.

## Future improvements

- UDP port scanning
- Banner grabbing and service-version detection
- IPv6 support
- OS fingerprinting
- Multi-host or subnet scanning
- SQLite storage for scan history

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Scan only systems you own or have explicit permission to assess. Unauthorized scanning may violate laws, regulations, or network policies. The author is not responsible for misuse.

## License

No license is currently specified. If you want others to reuse, modify, or distribute this project, choose and add an appropriate license file before publishing. Without a license, the default copyright restrictions apply.
