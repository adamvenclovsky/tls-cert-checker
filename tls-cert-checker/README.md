# tls-cert-checker

A small Python CLI tool for checking TLS certificate expiration, issuer, and validity status for one or more domains.

`tls-cert-checker` is designed for quick certificate checks from a terminal or a script. It returns readable text by default and structured JSON when output needs to be consumed by another tool.

## Features

- Checks the leaf TLS certificate for one or more domains
- Reports the issuer, subject, validity period, and days remaining
- Classifies certificates as `OK`, `WARNING`, or `EXPIRED`
- Reports DNS, connection, and invalid-input failures as `ERROR`
- Reads domains from command-line arguments or a text file
- Supports human-readable and JSON output
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
```

Using the virtual environment's Python directly avoids PowerShell execution-policy issues related to activation scripts.

## Usage

### Check one domain

```powershell
.\.venv\Scripts\python.exe -m tls_cert_checker example.com
```

Representative output (certificate details change when a site renews its certificate):

```text
Domain         : example.com
Port           : 443
Issuer         : CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
Subject        : CN=example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
Valid from     : 2026-01-15T00:00:00Z
Valid to       : 2026-07-15T23:59:59Z
Days remaining : 45
Status         : OK
```

Use a different TLS port with `--port`:

```powershell
.\.venv\Scripts\python.exe -m tls_cert_checker example.com --port 443
```

### Request JSON output

```powershell
.\.venv\Scripts\python.exe -m tls_cert_checker example.com --json
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
  "status": "OK"
}
```

A single check produces a JSON object. Multiple checks produce a JSON array. Failed checks include an `error` field with a user-readable explanation.

### Check domains from a file

Create a file with one domain per line:

```powershell
@("example.com", "python.org", "github.com") | Set-Content -Encoding utf8 domains.txt
.\.venv\Scripts\python.exe -m tls_cert_checker --file domains.txt
```

Blank lines and lines beginning with `#` are ignored. The optional `--port` value applies to every domain in the file.

You can also check multiple domains directly:

```powershell
.\.venv\Scripts\python.exe -m tls_cert_checker example.com python.org --json
```

## Status rules

| Status | Meaning |
| --- | --- |
| `OK` | More than 30 days remain |
| `WARNING` | 1 to 30 days remain |
| `EXPIRED` | The certificate has expired |
| `ERROR` | The domain could not be checked |

The command exits with status code `1` when any domain returns `ERROR`; otherwise, it exits with `0`.

## Running tests

Install the dependencies as shown above, then run:

```powershell
.\.venv\Scripts\python.exe -m pytest
```

The unit tests mock certificate-check results. They do not connect to live domains.

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
`-- requirements.txt
```

## Why I built this

TLS certificates are easy to overlook until an expiration causes warnings or an outage. I built this tool as a focused way to inspect certificate lifetimes during routine monitoring and to produce JSON that can feed lightweight automation. It also demonstrates practical Python networking, certificate parsing, CLI design, and test isolation without adding infrastructure that the problem does not require.

## Security note

The tool retrieves a certificate without CA or hostname verification so that it can inspect and report expired or otherwise invalid certificates. It reports certificate metadata and expiration status; it is not a replacement for a full TLS configuration or trust audit.

## License

This project is available under the [MIT License](LICENSE).
