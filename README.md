# ReconMaster

ReconMaster is a single-command recon workflow for quick defensive assessments.

It combines subdomain checks, port scanning, and basic HTTP header review in one run.

## Requirements

- Python 3.8+
- `requests`

Install:

```bash
pip install -r requirements.txt
```

## Quick start

```bash
python recon_master.py example.com
```

## Common commands

```bash
python recon_master.py example.com -p 1-1024 -t 20 --timeout 1.5
python recon_master.py example.com -p 80-443 -o recon_results.json
python recon_master.py 1.1.1.1 -p 53
```

## Options

- `target` domain or IP
- `-p, --ports` single port or range (default: `1-1024`)
- `-t, --threads` worker count (default: `10`)
- `--timeout` socket timeout in seconds (default: `1.0`)
- `-o, --output` write JSON output file

## Common issues

- **No subdomains listed**: expected for IP targets or limited DNS footprint.
- **Very few open ports**: target may be filtered or protected.
- **Header check fallback to HTTP**: usually means TLS trust issues in local environment.

## Responsible use

Use only on assets you own or are explicitly authorized to test.

## License

MIT.
