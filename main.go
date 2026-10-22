package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	version = "1.1.0"
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
	Name   string
	SHA256 string
	Note   string
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
	apply := fixCmd.Bool("apply", false, "Actually run the manual distrust commands (requires root). Default is dry-run / print only.")
	yes := fixCmd.Bool("yes", false, "Skip interactive confirmation when using --apply")

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
		runFix(*apply, *yes)
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
  fix            Print OS-specific remediation steps.
                 On Linux: auto-detects the distribution and shows the
                 exact manual distrust commands for that distro.
                 Use --apply to execute the manual block (requires root).
  version        Print version information.
  help           Show this help.

Examples:
  emudhra-scanner check
  emudhra-scanner check -v -timeout 5s
  emudhra-scanner info
  emudhra-scanner fix
  emudhra-scanner fix --apply          # Linux only, requires root
  emudhra-scanner fix --apply --yes    # non-interactive

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
				MinVersion: tls.VersionTLS12,
			},
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			DisableKeepAlives: true,
		},
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
	sem := make(chan struct{}, 6)

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
				r.ok = true
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
	fmt.Println("     On Linux you can also try: emudhra-scanner fix --apply  (requires root)")
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

func runFix(apply, yes bool) {
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
		printAndMaybeApplyLinuxFix(apply, yes)
	case "darwin":
		printDarwinFix()
		if apply {
			fmt.Println()
			fmt.Println("Note: --apply is currently only implemented for Linux.")
			fmt.Println("On macOS please run the printed commands manually (or keep the system updated).")
		}
	case "windows":
		printWindowsFix()
		if apply {
			fmt.Println()
			fmt.Println("Note: --apply is currently only implemented for Linux.")
			fmt.Println("On Windows prefer official Windows Updates.")
		}
	case "freebsd", "openbsd", "netbsd":
		printBSDFix()
		if apply {
			fmt.Println()
			fmt.Println("Note: --apply is currently only implemented for Linux.")
		}
	default:
		fmt.Printf("No automated guidance for %s. Please update your system's\n", runtime.GOOS)
		fmt.Println("CA certificate bundle from your vendor or distribution.")
	}

	fmt.Println()
	fmt.Println("After applying fixes, re-run:  emudhra-scanner check")
	fmt.Println("Reference: https://emudhra.we-have-a-problem.com/")
}

// ---------------------------------------------------------------------------
// Linux distro detection + manual block
// ---------------------------------------------------------------------------

type linuxDistro int

const (
	distroUnknown linuxDistro = iota
	distroDebian              // Debian, Ubuntu, Devuan, Mint, Pop!_OS, ...
	distroRHEL                // RHEL, CentOS, Rocky, Alma, Fedora, Oracle, Amazon
	distroAlpine
	distroArch
	distroOpenSUSE
)

func detectLinuxDistro() (linuxDistro, string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		// Fallback heuristics
		if fileExists("/etc/debian_version") {
			return distroDebian, "debian (fallback)"
		}
		if fileExists("/etc/redhat-release") || fileExists("/etc/centos-release") {
			return distroRHEL, "rhel (fallback)"
		}
		if fileExists("/etc/alpine-release") {
			return distroAlpine, "alpine (fallback)"
		}
		if fileExists("/etc/arch-release") {
			return distroArch, "arch (fallback)"
		}
		return distroUnknown, "unknown"
	}
	defer f.Close()

	var id, idLike, name string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		} else if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		}
	}

	display := name
	if display == "" {
		display = id
	}
	if display == "" {
		display = "unknown"
	}

	combined := strings.ToLower(id + " " + idLike)

	switch {
	case strings.Contains(combined, "debian") ||
		strings.Contains(combined, "ubuntu") ||
		strings.Contains(combined, "linuxmint") ||
		strings.Contains(combined, "pop") ||
		strings.Contains(combined, "devuan") ||
		strings.Contains(combined, "raspbian") ||
		strings.Contains(combined, "elementary"):
		return distroDebian, display
	case strings.Contains(combined, "rhel") ||
		strings.Contains(combined, "centos") ||
		strings.Contains(combined, "fedora") ||
		strings.Contains(combined, "rocky") ||
		strings.Contains(combined, "alma") ||
		strings.Contains(combined, "oracle") ||
		strings.Contains(combined, "amzn") ||
		strings.Contains(combined, "amazon"):
		return distroRHEL, display
	case strings.Contains(combined, "alpine"):
		return distroAlpine, display
	case strings.Contains(combined, "arch") ||
		strings.Contains(combined, "manjaro") ||
		strings.Contains(combined, "endeavouros"):
		return distroArch, display
	case strings.Contains(combined, "suse") ||
		strings.Contains(combined, "opensuse") ||
		strings.Contains(combined, "sles"):
		return distroOpenSUSE, display
	default:
		return distroUnknown, display
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func printAndMaybeApplyLinuxFix(apply, yes bool) {
	distro, name := detectLinuxDistro()
	fmt.Printf("Detected Linux distribution: %s\n\n", name)

	fmt.Println("1) Preferred — update ca-certificates package first")
	switch distro {
	case distroDebian:
		fmt.Println("   sudo apt update && sudo apt install --only-upgrade ca-certificates")
	case distroRHEL:
		fmt.Println("   sudo dnf update ca-certificates   # or: sudo yum update ca-certificates")
	case distroAlpine:
		fmt.Println("   sudo apk update && sudo apk upgrade ca-certificates")
	case distroArch:
		fmt.Println("   sudo pacman -Syu ca-certificates-mozilla")
	case distroOpenSUSE:
		fmt.Println("   sudo zypper refresh && sudo zypper update ca-certificates")
	default:
		fmt.Println("   Update the ca-certificates (or equivalent) package for your distribution.")
	}
	fmt.Println()

	fmt.Println("2) Manual distrust (block the affected roots)")
	fmt.Println("   The following commands are tailored for the detected distribution.")
	fmt.Println()

	cmds := linuxManualBlockCommands(distro)
	if len(cmds) == 0 {
		fmt.Println("   No automatic manual-block recipe for this distribution.")
		fmt.Println("   Please consult https://emudhra.we-have-a-problem.com/ for guidance.")
		return
	}

	for _, c := range cmds {
		fmt.Printf("   %s\n", c)
	}
	fmt.Println()

	if !apply {
		fmt.Println("Dry-run mode (default). To actually execute the manual block commands:")
		fmt.Println("  sudo emudhra-scanner fix --apply")
		fmt.Println("  sudo emudhra-scanner fix --apply --yes   # skip confirmation")
		return
	}

	// --apply path
	if os.Geteuid() != 0 {
		fmt.Println("ERROR: --apply requires root privileges. Re-run with sudo:")
		fmt.Println("  sudo emudhra-scanner fix --apply")
		os.Exit(1)
	}

	if !yes {
		fmt.Print("About to run the manual distrust commands above. Continue? [y/N]: ")
		var answer string
		fmt.Scanln(&answer)
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Aborted.")
			return
		}
	}

	fmt.Println()
	fmt.Println("Applying manual distrust ...")
	if err := runLinuxManualBlock(distro); err != nil {
		fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()
	fmt.Println("Done. Please re-run:  emudhra-scanner check")
}

func linuxManualBlockCommands(d linuxDistro) []string {
	switch d {
	case distroDebian:
		return []string{
			`sudo sed -i \`,
			`  -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \`,
			`  -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \`,
			`  /etc/ca-certificates.conf`,
			`sudo update-ca-certificates`,
		}
	case distroAlpine:
		return []string{
			`sudo apk add ca-certificates`,
			`sudo sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \`,
			`  /etc/ca-certificates.conf`,
			`sudo update-ca-certificates`,
		}
	case distroRHEL, distroOpenSUSE:
		return []string{
			`d=/etc/pki/ca-trust/source/blocklist`,
			`[ -d "$d" ] || d=/etc/pki/ca-trust/source/blacklist`,
			`sudo mkdir -p "$d"`,
			`sudo trust extract --overwrite --format=pem-bundle \`,
			`  --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \`,
			`  "$d/Comodo_AAA_Services_root.pem"`,
			`sudo trust extract --overwrite --format=pem-bundle \`,
			`  --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \`,
			`  "$d/emSign_ECC_Root_CA_-_G3.pem"`,
			`sudo update-ca-trust`,
		}
	case distroArch:
		// Arch uses ca-certificates-mozilla; disabling is less standardized.
		// We still try the common approach of commenting in the conf if present.
		return []string{
			`# Arch: prefer "pacman -Syu ca-certificates-mozilla"`,
			`# If still needed, you can try (paths may vary):`,
			`sudo sed -i \`,
			`  -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \`,
			`  -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \`,
			`  /etc/ca-certificates/update.d/*.conf 2>/dev/null || true`,
			`sudo update-ca-trust`,
		}
	default:
		return nil
	}
}

func runLinuxManualBlock(d linuxDistro) error {
	switch d {
	case distroDebian, distroAlpine:
		conf := "/etc/ca-certificates.conf"
		if !fileExists(conf) {
			return fmt.Errorf("%s not found", conf)
		}
		// Backup
		if err := copyFile(conf, conf+".emudhra-bak"); err != nil {
			return fmt.Errorf("backup failed: %w", err)
		}
		fmt.Printf("  Backed up %s → %s.emudhra-bak\n", conf, conf)

		data, err := os.ReadFile(conf)
		if err != nil {
			return err
		}
		lines := strings.Split(string(data), "\n")
		changed := false
		targets := []string{
			"mozilla/emSign_ECC_Root_CA_-_G3.crt",
			"mozilla/Comodo_AAA_Services_root.crt",
		}
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "!") {
				continue // already disabled
			}
			for _, t := range targets {
				if trimmed == t || strings.HasSuffix(trimmed, "/"+t) || strings.Contains(trimmed, t) {
					lines[i] = "!" + trimmed
					changed = true
					fmt.Printf("  Disabled: %s\n", trimmed)
					break
				}
			}
		}
		if !changed {
			fmt.Println("  No matching enabled entries found (may already be disabled or filenames differ).")
			fmt.Println("  Inspect /etc/ca-certificates.conf and the certificates directory if needed.")
		} else {
			out := strings.Join(lines, "\n")
			if err := os.WriteFile(conf, []byte(out), 0644); err != nil {
				return err
			}
		}
		fmt.Println("  Running update-ca-certificates ...")
		cmd := exec.Command("update-ca-certificates")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()

	case distroRHEL, distroOpenSUSE:
		blockDir := "/etc/pki/ca-trust/source/blocklist"
		if !fileExists(blockDir) {
			if fileExists("/etc/pki/ca-trust/source/blacklist") {
				blockDir = "/etc/pki/ca-trust/source/blacklist"
			} else {
				if err := os.MkdirAll(blockDir, 0755); err != nil {
					return err
				}
			}
		}
		fmt.Printf("  Using blocklist directory: %s\n", blockDir)

		extracts := []struct {
			filter string
			out    string
		}{
			{"pkcs11:object=Comodo%20AAA%20Services%20root;type=cert", "Comodo_AAA_Services_root.pem"},
			{"pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert", "emSign_ECC_Root_CA_-_G3.pem"},
		}
		for _, e := range extracts {
			outPath := blockDir + "/" + e.out
			fmt.Printf("  Extracting → %s\n", outPath)
			cmd := exec.Command("trust", "extract", "--overwrite", "--format=pem-bundle",
				"--filter="+e.filter, outPath)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Printf("  Warning: trust extract failed for %s: %v\n", e.out, err)
				// continue; some systems may not have the object
			}
		}
		fmt.Println("  Running update-ca-trust ...")
		cmd := exec.Command("update-ca-trust")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()

	case distroArch:
		fmt.Println("  Arch: preferring package update path.")
		fmt.Println("  Please run: sudo pacman -Syu ca-certificates-mozilla")
		fmt.Println("  Manual conf editing is less reliable on Arch; skipped.")
		return nil

	default:
		return fmt.Errorf("no apply recipe for this distribution")
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// ---------------------------------------------------------------------------
// Other platforms (print-only)
// ---------------------------------------------------------------------------

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
	fmt.Println("3) Homebrew users: update the ca-certificates formula")
	fmt.Println("     brew upgrade ca-certificates")
}

func printWindowsFix() {
	fmt.Println("Windows remediation options")
	fmt.Println("===========================")
	fmt.Println()
	fmt.Println("1) Preferred — install the latest Windows Updates.")
	fmt.Println("   Microsoft blocked the intermediates starting 2026-10-20.")
	fmt.Println()
	fmt.Println("2) Official PowerShell mitigation from the disclosure site")
	fmt.Println("   (adds the compromised intermediates to Untrusted Certificates):")
	fmt.Println()
	fmt.Println(`   # Download and inspect first, then run elevated:`)
	fmt.Println(`   # https://github.com/galadran/we-have-a-problem.com/blob/main/Block-EmudhraCompromisedCA.ps1`)
	fmt.Println(`   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Block-EmudhraCompromisedCA.ps1`)
}

func printBSDFix() {
	fmt.Println("BSD remediation options")
	fmt.Println("=======================")
	fmt.Println()
	fmt.Println("FreeBSD:")
	fmt.Println("  Update the caroot / ca_root_nss package:")
	fmt.Println("    pkg upgrade caroot ca_root_nss")
	fmt.Println()
	fmt.Println("Other BSDs: update the system CA bundle via the normal")
	fmt.Println("ports / packages mechanism for your release.")
}
