# certlive

`certlive` is a small Python tool that connects to the public
[certstream](https://certstream.calidog.io/) feed (an aggregator of
[Certificate Transparency](https://certificate.transparency.dev/) logs)
and displays in real time the list of domains associated with **each
newly issued TLS certificate**, regardless of its type (DV, OV, EV,
wildcard, Let's Encrypt, DigiCert, etc.).

## Installation

```bash
git clone https://github.com/Marlbogaro/certlive.git
cd certlive
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Continuously display all domains
python certlive.py

# Save domains to a file (append)
python certlive.py -o domains.txt

# Filter by keyword (case-insensitive)
python certlive.py -k paypal

# Ignore wildcard domains (*.example.com)
python certlive.py --no-wildcard

# Verbose mode: timestamp + issuer
python certlive.py -v
```

Stop with `Ctrl+C`.

### Options

| Option | Description |
|---|---|
| `-o`, `--output FILE` | Append each domain to a file (one per line). |
| `-k`, `--keyword WORD` | Only keep domains containing this keyword. |
| `--no-wildcard` | Ignore domains starting with `*.`. |
| `-v`, `--verbose` | Also display the timestamp and the certificate issuer. |
| `-u`, `--url URL` | certstream server URL (default: `wss://certstream.calidog.io/`). |

## How it works

Every newly issued public certificate is published to Certificate
Transparency logs. The [certstream](https://certstream.calidog.io/)
service aggregates these logs and broadcasts them over WebSocket.
`certlive`:

1. Opens a WebSocket connection to the certstream server.
2. Receives `certificate_update` events.
3. Extracts the list of domains (`CN` + `SAN`) from each certificate.
4. Applies any filters and then displays / saves the domains.

## License

See [LICENSE](LICENSE).
