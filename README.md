# ReconMaster (Python)

ReconMaster is a single-command reconnaissance workflow for defensive assessments.

## What it does

- Resolves target IP
- Enumerates common subdomains (domain targets)
- Scans requested TCP ports
- Checks web response headers for missing hardening controls
- Produces optional JSON report output

## Requirements

- Python 3.8+
- `requests` (from `requirements.txt`)

## Usage

```bash
python recon_master.py <target>
python recon_master.py <target> -p 1-1024 -t 20 --timeout 1.5
python recon_master.py <target> -o recon_results.json
```

## Options

- `target` domain or IP
- `-p, --ports` single port or range (default: `1-1024`)
- `-t, --threads` worker count (default: `10`)
- `--timeout` socket timeout in seconds (default: `1.0`)
- `-o, --output` save results as JSON

## Safety

Use only with written authorization.

## License

MIT (see `LICENSE`).
