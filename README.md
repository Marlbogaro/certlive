# certlive

`certlive` is a Python tool that queries [Certificate Transparency](https://certificate.transparency.dev/)
logs directly via their HTTP API (RFC 6962) and prints the domains from every newly issued TLS certificate
in real time. It requires no certstream server and no Docker.

## Installation

```bash
git clone https://github.com/Marlbogaro/certlive.git
cd certlive
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Real-time mode

```bash
# Stream all domains from all active CT logs
python certlive.py

# Save to a file and filter by keyword
python certlive.py -o domains.txt -k paypal

# Verbose output (timestamp + issuer per domain)
python certlive.py -v

# Skip wildcard domains (*.example.com)
python certlive.py --no-wildcard

# Use specific CT logs only
python certlive.py --logs https://ct.cloudflare.com/logs/nimbus2026/
```

Stop with `Ctrl+C`.

### Historical mode

Scan certificates issued during a past time window.

```bash
# Scan a full UTC day
python certlive.py --date 2026-04-17

# Scan a custom time range (ISO 8601, Z = UTC)
python certlive.py --since 2026-04-18T20:00Z --until 2026-04-18T21:00Z

# Historical scan on a specific log, save results
python certlive.py --date 2026-04-17 \
    --logs https://ct.cloudflare.com/logs/nimbus2026/ \
    -o results.txt
```

## Options

| Option | Description |
|---|---|
| `-o FILE`, `--output FILE` | Append domains to a file (one per line). |
| `-k WORD`, `--keyword WORD` | Only keep domains containing this keyword (case-insensitive). |
| `--no-wildcard` | Skip wildcard domains (`*.example.com`). |
| `-v`, `--verbose` | Also print timestamp, log source, and issuer. |
| `--logs URL[,URL...]` | Comma-separated CT log URLs to use. Default: all usable Google-listed logs. |
| `--date YYYY-MM-DD` | Scan a full UTC day (historical mode). |
| `--since ISO8601` | Start of a custom time range, inclusive (e.g. `2026-04-17T00:00Z`). |
| `--until ISO8601` | End of a custom time range, exclusive. Must be used with `--since`. |

> `--date` and `--since`/`--until` are mutually exclusive.

## How it works

1. Fetches the official CT log list from Google and keeps only logs whose temporal interval covers the target date.
2. For each log, polls `get-sth` to track the tree size, then downloads new entries with `get-entries`.
3. Decodes the `MerkleTreeLeaf` TLS structure and extracts the certificate or pre-certificate.
4. Parses `CN` + `SAN DNS` domains, applies filters, and prints/saves results.
5. In historical mode, uses binary search (~log₂ N requests) to locate the index range matching the requested timestamps.

## License

See [LICENSE](LICENSE).
