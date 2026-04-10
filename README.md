# ReconMaster

A comprehensive reconnaissance tool for penetration testers. Combines subdomain enumeration, port scanning, HTTP header analysis, and basic vulnerability detection in one CLI tool.

## Features

- Subdomain enumeration
- Multithreaded port scanning
- HTTP header security checks
- Basic vulnerability detection
- JSON output support
- Configurable threads and timeouts

## Installation

Clone the repository and install dependencies:

```bash
pip install requests
```

## Usage

```bash
python recon_master.py <target> [options]
```

### Examples

```bash
# Basic scan
python recon_master.py example.com

# Custom port range
python recon_master.py example.com -p 1-1000

# Save results to JSON
python recon_master.py example.com -o results.json

# Increase threads
python recon_master.py example.com -t 20
```

## Options

- `-p, --ports`: Port range (default: 1-1024)
- `-t, --threads`: Number of threads (default: 10)
- `-o, --output`: Output file (JSON)
- `--timeout`: Socket timeout (default: 1.0)

## License

MIT