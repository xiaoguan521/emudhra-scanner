package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	version = "1.0.0"
	banner  = `
  ╔═══════════════════════════════════════════════════════╗
  ║   eMudhra Intermediate CA Compromise Scanner          ║
  ║   https://emudhra.we-have-a-problem.com/               ║
  ╚═══════════════════════════════════════════════════════╝
`
)

// Test hosts from the disclosure site. A successful TLS handshake
// means the system still trusts a compromised intermediate.
var testHosts = []string{
	"https://dv-g3b-emudhra.we-have-a-problem.com/",
	"https://dv-g3c-emudhra.we-have-a-problem.com/",
	"https://ov-g3b-emudhra.we-have-a-problem.com/",
	"https://ov-g3c-emudhra.we-have-a-problem.com/",
	"https://ev-g3b-emudhra.we-have-a-problem.com/",
	"https://ev-g3c-emudhra.we-have-a-problem.com/",
	"https://dv-g3b-aaa-emudhra.we-have-a-problem.com/",
	"https://dv-g3c-aaa-emudhra.we-have-a-problem.com/",
	"https://ov-g3b-aaa-emudhra.we-have-a-problem.com/",
	"https://ov-g3c-aaa-emudhra.we-have-a-problem.com/",
	"https://ev-g3b-aaa-emudhra.we-have-a-problem.com/",
	"https://ev-g3c-aaa-emudhra.we-have-a-problem.com/",
}

// Known root fingerprints that are being distrusted / removed in updates.
var affectedRoots = []struct {
	Name       string
	SHA256     string
	Note       string
}{
	{"AAA Certificate Services", "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4", "Sectigo root used for cross-signs"},
	{"emSign ECC Root CA - G3", "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B", "eMudhra ECC root (cross-signer)"},
	{"emSign Root TLS CA - G3", "7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D", "eMudhra TLS root"},
	{"emSign Root CS CA - G3", "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5", "eMudhra code-signing root"},
}

func main() {
	checkCmd := flag.NewFlagSet("check", flag.ExitOnError)
	timeout := checkCmd.Duration("timeout", 8*time.Second, "TLS connection timeout per host")
	verbose := checkCmd.Bool("v", false, "Verbose output")

	infoCmd := flag.NewFlagSet("info", flag.ExitOnError)
	fixCmd := flag.NewFlagSet("fix", flag.ExitOnError)
	versionCmd := flag.NewFlagSet("version", flag.ExitOnError)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	switch os.Args[1] {
	case "check", "scan":
		checkCmd.Parse(os.Args[2:])
		runCheck(*timeout, *verbose)
	case "info":
		infoCmd.Parse(os.Args[2:])
		runInfo()
	case "fix":
		fixCmd.Parse(os.Args[2:])
		runFix()
	case "version", "-v", "--version":
		versionCmd.Parse(os.Args[2:])
		fmt.Printf("emudhra-scanner %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(banner)
	fmt.Println(`Usage:
  emudhra-scanner <command> [options]

Commands:
  check, scan    Test whether this system still trusts the compromised
                 eMudhra intermediate CAs (network check against
                 disclosure test hosts).
  info           Show details about the affected CAs and roots.
  fix            Print OS-specific remediation steps (does NOT
                 automatically modify the system trust store).
  version        Print version information.
  help           Show this help.

Examples:
  emudhra-scanner check
  emudhra-scanner check -v -timeout 5s
  emudhra-scanner info
  emudhra-scanner fix

Important:
  - A successful connection to a test host means the system is still
    vulnerable (still trusts a compromised intermediate).
  - Certificate errors / connection failures on the test hosts are GOOD
    (the intermediates are no longer trusted).
  - Prefer updating your OS / ca-certificates package over manual fixes.
  - Manual distrust of roots can break legitimate certificates that
    still chain through those roots. Use with caution.`)
}

func runCheck(timeout time.Duration, verbose bool) {
	fmt.Print(banner)
	fmt.Printf("Scanning %d test hosts (timeout %s) ...\n\n", len(testHosts), timeout)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Use system trust store (default)
				MinVersion: tls.VersionTLS12,
			},
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			// Disable keep-alives so each check is independent
			DisableKeepAlives: true,
		},
		// Do not follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type result struct {
		host   string
		ok     bool // true = connected successfully = still trusts compromised CA
		err    error
		status int
	}

	results := make([]result, len(testHosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6) // limit concurrency

	for i, host := range testHosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, err := client.Get(host)
			r := result{host: host}
			if err != nil {
				r.err = err
				r.ok = false
			} else {
				r.status = resp.StatusCode
				r.ok = true // TLS succeeded
				resp.Body.Close()
			}
			results[i] = r
		}(i, host)
	}
	wg.Wait()

	vulnerableCount := 0
	for _, r := range results {
		short := strings.TrimPrefix(r.host, "https://")
		short = strings.TrimSuffix(short, "/")
		if r.ok {
			vulnerableCount++
			fmt.Printf("  [VULNERABLE] %-45s  status=%d\n", short, r.status)
		} else {
			if verbose {
				errStr := ""
				if r.err != nil {
					errStr = r.err.Error()
					// Truncate very long error messages
					if len(errStr) > 80 {
						errStr = errStr[:77] + "..."
					}
				}
				fmt.Printf("  [OK]         %-45s  %s\n", short, errStr)
			} else {
				fmt.Printf("  [OK]         %s\n", short)
			}
		}
	}

	fmt.Println()
	if vulnerableCount == 0 {
		fmt.Println("Result: SAFE — this system does not trust the compromised intermediates.")
		fmt.Println("         (All test hosts produced certificate / connection errors.)")
		os.Exit(0)
	}

	fmt.Printf("Result: VULNERABLE — %d/%d test hosts still accepted.\n", vulnerableCount, len(testHosts))
	fmt.Println("         This system still trusts one or more compromised eMudhra intermediates.")
	fmt.Println()
	fmt.Println("Recommended actions:")
	fmt.Println("  1. Update your operating system and ca-certificates package immediately.")
	fmt.Println("  2. Update browsers, runtimes (Go, Java, Node, Python certifi, etc.).")
	fmt.Println("  3. Run 'emudhra-scanner fix' for OS-specific manual remediation tips.")
	fmt.Println()
	fmt.Println("Reference: https://emudhra.we-have-a-problem.com/")
	os.Exit(2)
}

func runInfo() {
	fmt.Print(banner)
	fmt.Println("Incident summary (as of 2026-10-20)")
	fmt.Println("-----------------------------------")
	fmt.Println("Eight eMudhra intermediate CA private keys were generated with")
	fmt.Println("catastrophically weak values (effectively enumerable from the")
	fmt.Println("public certificates). An attacker can sign arbitrary certificates")
	fmt.Println("that chain to widely-trusted roots.")
	fmt.Println()
	fmt.Println("Affected intermediate CAs (TLS):")
	fmt.Println("  - EM DV TLS CA - G3B / G3C")
	fmt.Println("  - EM OV TLS CA - G3B / G3C")
	fmt.Println("  - EM EV TLS CA - G3B / G3C")
	fmt.Println("  (plus corresponding Sectigo AAA cross-signed certificates)")
	fmt.Println()
	fmt.Println("Also affected: two code-signing intermediates (EM OV CS CA - G3B/G3C).")
	fmt.Println()
	fmt.Println("Roots involved (SHA-256 fingerprints):")
	for _, r := range affectedRoots {
		fmt.Printf("  %-28s  %s\n", r.Name, r.SHA256)
		fmt.Printf("    → %s\n", r.Note)
	}
	fmt.Println()
	fmt.Println("Timeline highlights:")
	fmt.Println("  2025-04   Weak intermediates generated")
	fmt.Println("  2026-10-17 Disclosure to root programs; Firefox/Chrome blocks begin")
	fmt.Println("  2026-10-18 eMudhra revokes intermediates")
	fmt.Println("  2026-10-19 Apple block; Sectigo cross-signs revoked")
	fmt.Println("  2026-10-20 Microsoft block; public disclosure site")
	fmt.Println()
	fmt.Println("Full details & proof: https://emudhra.we-have-a-problem.com/")
	fmt.Println("Mozilla bug:          https://bugzilla.mozilla.org/show_bug.cgi?id=2083449")
}

func runFix() {
	fmt.Print(banner)
	fmt.Printf("Detected platform: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	fmt.Println("IMPORTANT WARNINGS")
	fmt.Println("------------------")
	fmt.Println("• Prefer official OS / package updates over manual trust-store edits.")
	fmt.Println("• Distrusting a root can break any certificate that still chains to it.")
	fmt.Println("• These commands usually require root / Administrator privileges.")
	fmt.Println("• Always back up the trust store before making changes.")
	fmt.Println()

	switch runtime.GOOS {
	case "linux":
		printLinuxFix()
	case "darwin":
		printDarwinFix()
	case "windows":
		printWindowsFix()
	case "freebsd", "openbsd", "netbsd":
		printBSDFix()
	default:
		fmt.Printf("No automated guidance for %s. Please update your system's\n", runtime.GOOS)
		fmt.Println("CA certificate bundle from your vendor or distribution.")
	}

	fmt.Println()
	fmt.Println("After applying fixes, re-run:  emudhra-scanner check")
	fmt.Println("Reference: https://emudhra.we-have-a-problem.com/")
}

func printLinuxFix() {
	fmt.Println("Linux remediation options")
	fmt.Println("=========================")
	fmt.Println()
	fmt.Println("1) Preferred — update ca-certificates package")
	fmt.Println("   Debian/Ubuntu:")
	fmt.Println("     sudo apt update && sudo apt install --only-upgrade ca-certificates")
	fmt.Println("   Fedora/RHEL/CentOS/Rocky/Alma:")
	fmt.Println("     sudo dnf update ca-certificates")
	fmt.Println("   Alpine:")
	fmt.Println("     sudo apk update && sudo apk upgrade ca-certificates")
	fmt.Println("   Arch:")
	fmt.Println("     sudo pacman -Syu ca-certificates-mozilla")
	fmt.Println()
	fmt.Println("2) Manual distrust (until package update arrives)")
	fmt.Println()
	fmt.Println("   Debian / Ubuntu / Devuan:")
	fmt.Println(`     sudo sed -i \
       -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
       -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
       /etc/ca-certificates.conf && sudo update-ca-certificates`)
	fmt.Println()
	fmt.Println("   Alpine:")
	fmt.Println(`     sudo apk add ca-certificates
     sudo sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
       /etc/ca-certificates.conf && sudo update-ca-certificates`)
	fmt.Println()
	fmt.Println("   Fedora / RHEL family:")
	fmt.Println(`     d=/etc/pki/ca-trust/source/blocklist
     [ -d "$d" ] || d=/etc/pki/ca-trust/source/blacklist
     sudo mkdir -p "$d"
     sudo trust extract --overwrite --format=pem-bundle \
       --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
       "$d/Comodo_AAA_Services_root.pem"
     sudo trust extract --overwrite --format=pem-bundle \
       --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
       "$d/emSign_ECC_Root_CA_-_G3.pem"
     sudo update-ca-trust`)
	fmt.Println()
	fmt.Println("   openSUSE / SLES: similar blocklist approach under /etc/pki/trust/")
	fmt.Println()
	fmt.Println("Note: Exact filenames in ca-certificates.conf may vary by release.")
	fmt.Println("Inspect the file and the certificates directory if the sed patterns miss.")
}

func printDarwinFix() {
	fmt.Println("macOS remediation options")
	fmt.Println("=========================")
	fmt.Println()
	fmt.Println("1) Preferred — keep macOS fully updated (System Settings → Software Update).")
	fmt.Println("   Apple blocked the intermediates starting 2026-10-19 via system mechanisms.")
	fmt.Println()
	fmt.Println("2) Workaround for tools that use /etc/ssl/cert.pem directly")
	fmt.Println("   (built-in curl, git, python3, perl, ruby, openssl, etc.)")
	fmt.Println()
	fmt.Println(`   sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak
   sudo awk '/^(###|===) /{skip=0}
     /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
     !skip' /etc/ssl/cert.pem.bak | sudo tee /etc/ssl/cert.pem > /dev/null`)
	fmt.Println()
	fmt.Println("3) Make system Python / pip use the cleaned cert.pem")
	fmt.Println(`   F="$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')/sitecustomize.py"
   echo 'import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")' | sudo tee -a "$F" > /dev/null
   sudo chmod 644 "$F"`)
	fmt.Println()
	fmt.Println("4) Homebrew users: update the ca-certificates formula")
	fmt.Println("     brew upgrade ca-certificates")
	fmt.Println()
	fmt.Println("For nix-darwin, also follow the corresponding NixOS / ca-certificates guidance.")
}

func printWindowsFix() {
	fmt.Println("Windows remediation options")
	fmt.Println("===========================")
	fmt.Println()
	fmt.Println("1) Preferred — install the latest Windows Updates.")
	fmt.Println("   Microsoft blocked the intermediates starting 2026-10-20.")
	fmt.Println()
	fmt.Println("2) Verify / manage certificates with certmgr or PowerShell")
	fmt.Println("   Open certmgr.msc → Trusted Root Certification Authorities")
	fmt.Println("   and Intermediate Certification Authorities; look for the")
	fmt.Println("   eMudhra / emSign / AAA Certificate Services entries listed")
	fmt.Println("   in the 'info' command and remove only if you understand the impact.")
	fmt.Println()
	fmt.Println("   PowerShell example (run elevated, use with extreme caution):")
	fmt.Println(`     Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
       $_.Subject -match 'emSign|eMudhra|AAA Certificate Services'
     } | Format-List Subject, Thumbprint, NotAfter`)
	fmt.Println()
	fmt.Println("   Removing roots can break many legitimate certificates.")
	fmt.Println("   Prefer waiting for official Microsoft updates.")
}

func printBSDFix() {
	fmt.Println("BSD remediation options")
	fmt.Println("=======================")
	fmt.Println()
	fmt.Println("FreeBSD:")
	fmt.Println("  Update the caroot / ca_root_nss package:")
	fmt.Println("    pkg upgrade caroot ca_root_nss")
	fmt.Println("  Or follow the security advisory FreeBSD-SA-26:73.caroot")
	fmt.Println()
	fmt.Println("Other BSDs: update the system CA bundle via the normal")
	fmt.Println("ports / packages mechanism for your release.")
}
