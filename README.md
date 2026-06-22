# tls-cert-checker

A small Python CLI tool for checking TLS certificate expiration, issuer, and validity status for one or more domains.

`tls-cert-checker` is a lightweight TLS certificate inspection tool for quick checks from a terminal or script. It supports readable terminal output and JSON, Markdown, or CSV reports without attempting to be a full SSL Labs-style scanner.

## Features

- Checks the leaf TLS certificate for one or more domains
- Reports the issuer, subject, validity period, and days remaining
- Shows SHA256 fingerprint, serial number, signature, public-key, and DNS SAN details
- Reports the negotiated TLS version and cipher suite
- Checks wildcard presence and whether the requested hostname matches a DNS SAN
- Classifies certificates with a configurable warning threshold
- Reports DNS, connection, and invalid-input failures as `ERROR`
- Reads domains from command-line arguments or a text file
- Supports text, JSON, Markdown, and CSV output
- Writes reports to stdout or a file
- Supports configurable connection timeouts
- Installs the `tls-cert-checker` console command
- Uses the Python standard library plus `cryptography`

## Requirements

- Python 3.11 or newer
- Network access to the domains and ports being checked

## Installation (Windows PowerShell)

From the repository root, create a virtual environment and install the project:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\Activate.ps1
```

After activation, the `tls-cert-checker` command is available in the current PowerShell session. If activation scripts are restricted, use `.\.venv\Scripts\tls-cert-checker.exe` directly.

## Usage

### Check one domain

```powershell
tls-cert-checker example.com
```

Representative output (certificate details change when a site renews its certificate):

```text
TLS Certificate Check
=====================
Domain               : example.com
Port                 : 443
Issuer               : CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
Subject              : CN=example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
Valid from           : 2026-01-15T00:00:00Z
Valid to             : 2026-07-15T23:59:59Z
Days remaining       : 45
Status               : OK
TLS version          : TLSv1.3
Cipher               : TLS_AES_256_GCM_SHA384
Public key           : EC 256-bit
Signature algorithm  : ecdsa-with-SHA384
SHA256 fingerprint   : 7A:21:9C:48:6E:1D:73:9B:54:36:8A:CF:51:02:AD:9F:86:C1:18:D7:44:32:0A:AB:17:96:82:EE:40:53:BC:11
Serial number        : 75B2A21C37D9F14E
SAN count            : 2
Wildcard certificate : No
Hostname match       : Yes
```

Show the complete DNS Subject Alternative Name list in text output:

```powershell
tls-cert-checker example.com --show-san
```

The SAN list is omitted from normal text output to keep it readable.

Use a different TLS port with `--port`:

```powershell
tls-cert-checker example.com --port 443
```

Set the warning window with `--warning-days`. This example reports `WARNING` when 14 days or fewer remain:

```powershell
tls-cert-checker example.com --warning-days 14
```

Limit the time allowed to establish a connection:

```powershell
tls-cert-checker example.com --timeout 3
```

### Request JSON output

```powershell
tls-cert-checker example.com --json
```

Representative JSON output:

```json
{
  "domain": "example.com",
  "port": 443,
  "issuer": "CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US",
  "subject": "CN=example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US",
  "valid_from": "2026-01-15T00:00:00Z",
  "valid_to": "2026-07-15T23:59:59Z",
  "days_remaining": 45,
  "status": "OK",
  "serial_number": "75B2A21C37D9F14E",
  "sha256_fingerprint": "7A:21:9C:48:6E:1D:73:9B:54:36:8A:CF:51:02:AD:9F:86:C1:18:D7:44:32:0A:AB:17:96:82:EE:40:53:BC:11",
  "signature_algorithm": "ecdsa-with-SHA384",
  "public_key_algorithm": "EC",
  "public_key_size": 256,
  "subject_alt_names": ["example.com", "www.example.com"],
  "san_count": 2,
  "is_wildcard": false,
  "hostname_match": true,
  "tls_version": "TLSv1.3",
  "cipher": "TLS_AES_256_GCM_SHA384"
}
```

A single check produces a JSON object. Multiple checks produce a JSON array. JSON includes all certificate and TLS connection fields, including the SAN list. Failed checks include an `error` field with a user-readable explanation.

The equivalent explicit format option is:

```powershell
tls-cert-checker example.com --format json
```

### Check domains from a file

Create a file with one domain per line:

```powershell
@("example.com", "python.org", "github.com") | Set-Content -Encoding utf8 domains.txt
tls-cert-checker --file domains.txt
```

Blank lines and lines beginning with `#` are ignored. The optional `--port` value applies to every domain in the file.

You can also check multiple domains directly:

```powershell
tls-cert-checker example.com python.org --json
```

### Generate Markdown and CSV reports

Write a compact Markdown table containing status, TLS version, public key, SAN count, and hostname match:

```powershell
tls-cert-checker --file domains.txt --format markdown --output report.md
```

Write the complete certificate and connection fields to CSV for use in a spreadsheet or another script. SAN entries are stored as a comma-separated value:

```powershell
tls-cert-checker --file domains.txt --format csv --output report.csv
```

Without `--output`, the selected format is written to the terminal. An existing output file is overwritten. `--json` remains available as an alias for `--format json`.

### Module command alternative

The package remains directly executable without the console-script wrapper:

```powershell
.\.venv\Scripts\python.exe -m tls_cert_checker example.com
.\.venv\Scripts\python.exe -m tls_cert_checker example.com --json
```

## CLI reference

The built-in help groups options by input, status, output, and other commands.

| Option | Description | Default |
| --- | --- | --- |
| `DOMAIN` | One or more domains to check | - |
| `--file PATH` | Read domains from a text file | - |
| `--port PORT` | TLS port used for every domain | `443` |
| `--timeout SECONDS` | Connection timeout per domain | `5` |
| `--warning-days DAYS` | Mark certificates as `WARNING` when they expire within this many days | `30` |
| `--format FORMAT` | `text`, `json`, `markdown`, or `csv` | `text` |
| `--json` | Alias for `--format json` | - |
| `--show-san` | Include the full DNS SAN list in text output | off |
| `--output PATH` | Write output to a file | stdout |
| `--version` | Show the installed version and exit | - |
| `-h`, `--help` | Show help and examples | - |

Show the complete built-in help or version:

```powershell
tls-cert-checker --help
tls-cert-checker --version
```

## Status rules

| Status | Meaning |
| --- | --- |
| `OK` | More than `warning_days` remain |
| `WARNING` | 1 to `warning_days` remain |
| `EXPIRED` | The certificate has expired |
| `ERROR` | The domain could not be checked |

The command exits with status code `1` when any domain returns `ERROR`; otherwise, it exits with `0`.

The default warning threshold is 30 days. `--warning-days 0` disables the warning range, so every unexpired certificate is `OK`.

## Running tests

Install the dependencies as shown above, then run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
```

The unit tests mock certificate-check results. They do not connect to live domains.

Run the lightweight lint and compile checks with:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m compileall src tests
```

## Project structure

```text
tls-cert-checker/
|-- .github/
|   `-- workflows/
|       `-- ci.yml
|-- src/
|   `-- tls_cert_checker/
|       |-- __init__.py
|       |-- __main__.py
|       |-- checker.py
|       |-- cli.py
|       `-- output.py
|-- tests/
|   |-- test_checker.py
|   |-- test_cli.py
|   `-- test_output.py
|-- .gitignore
|-- domains.txt.example
|-- LICENSE
|-- pyproject.toml
|-- README.md
|-- requirements-dev.txt
`-- requirements.txt
```

## Why I built this

TLS certificates are easy to overlook until an expiration causes warnings or an outage. I built this tool as a focused way to inspect certificate lifetimes during routine monitoring and to produce JSON that can feed lightweight automation. It also demonstrates practical Python networking, certificate parsing, CLI design, and test isolation without adding infrastructure that the problem does not require.

## Security note

The tool retrieves a certificate without CA or hostname verification so that it can inspect and report expired or otherwise invalid certificates. `Hostname match` compares the requested domain with DNS SAN entries, but the tool does not validate the certificate chain. Domain names are converted with Python's built-in IDNA codec; IP address SAN matching is outside the tool's scope. It does not perform OCSP, CRL, Certificate Transparency, or comprehensive TLS configuration analysis and is not an SSL Labs replacement.

## License

This project is available under the [MIT License](LICENSE).
