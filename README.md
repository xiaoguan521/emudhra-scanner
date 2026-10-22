# eMudhra Intermediate CA Compromise Scanner

Cross-platform Go tool to **detect** whether a system still trusts the compromised eMudhra intermediate CAs (October 2026 incident) and to print **OS-specific remediation guidance**.

Reference disclosure site: https://emudhra.we-have-a-problem.com/

## What happened?

In April 2025, eMudhra generated eight intermediate CA certificates with catastrophically weak private keys (effectively recoverable from the public certificates alone). An attacker with any of those keys can issue certificates for arbitrary domains that chain to widely trusted roots (emSign Root TLS CA - G3, AAA Certificate Services / Sectigo, etc.).

Major browsers (Firefox, Chrome, Safari, Edge) blocked the intermediates quickly via OneCRL / CRLSets / similar mechanisms. Many operating-system trust stores and language runtimes needed (or still need) updates.

## Features

- **check / scan** — Network test against the 12 disclosure test hosts.  
  A successful TLS handshake = the system still trusts a compromised intermediate (vulnerable).  
  Certificate errors = good (intermediates no longer trusted).
- **info** — Summary of the incident and affected roots (with SHA-256 fingerprints).
- **fix** — Platform-aware remediation tips (Linux, macOS, Windows, BSD).  
  The tool **does not** automatically modify your trust store; it only prints commands you can review and run.

## Install / Build

### Pre-built binaries

Download from the [Releases](../../releases) page (Linux, macOS, Windows, FreeBSD; amd64 & arm64 where applicable).

### Build from source

```bash
git clone https://github.com/xiaoguan521/emudhra-scanner.git
cd emudhra-scanner
go build -o emudhra-scanner .
```

Cross-compile examples:

```bash
GOOS=linux   GOARCH=amd64 go build -o emudhra-scanner-linux-amd64 .
GOOS=linux   GOARCH=arm64 go build -o emudhra-scanner-linux-arm64 .
GOOS=darwin  GOARCH=amd64 go build -o emudhra-scanner-darwin-amd64 .
GOOS=darwin  GOARCH=arm64 go build -o emudhra-scanner-darwin-arm64 .
GOOS=windows GOARCH=amd64 go build -o emudhra-scanner-windows-amd64.exe .
GOOS=freebsd GOARCH=amd64 go build -o emudhra-scanner-freebsd-amd64 .
```

## Usage

```text
emudhra-scanner check          # default scan
emudhra-scanner check -v       # verbose (show error details)
emudhra-scanner check -timeout 5s

emudhra-scanner info
emudhra-scanner fix
emudhra-scanner version
emudhra-scanner help
```

Exit codes for `check`:

| Code | Meaning                                      |
|------|----------------------------------------------|
| 0    | Safe (no successful connections to test hosts) |
| 2    | Vulnerable (one or more hosts accepted)      |
| 1    | Usage / other error                          |

## Example output (vulnerable system)

```text
  [VULNERABLE] dv-g3b-emudhra.we-have-a-problem.com          status=200
  [OK]         dv-g3c-emudhra.we-have-a-problem.com
  ...
Result: VULNERABLE — 3/12 test hosts still accepted.
```

## Security notes

- Prefer official OS / package updates (`ca-certificates`, Windows Update, macOS Software Update, etc.) over manual root distrust.
- Manually distrusting a root can break legitimate certificates that still chain through it.
- The tool only performs outbound HTTPS connections to the disclosure test hosts and prints guidance; it does not require elevated privileges for scanning.

## License

MIT

## Credits

Incident research and public disclosure site by the Mozilla / community team (Dennis Jackson et al.).  
This scanner is an independent helper utility.
