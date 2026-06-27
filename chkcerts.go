// Usage
//
// go run chkcerts.go https://chrisshort.net
//
// go run chkcerts.go https://chrisshort.net 90
//
// go run chkcerts.go -k https://self-signed.example.com
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

func main() {
	insecure := flag.Bool("k", false, "skip TLS certificate verification (for self-signed certs)")
	flag.BoolVar(insecure, "insecure", false, "skip TLS certificate verification (for self-signed certs)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 || len(args) > 2 {
		fmt.Println("Usage: chkcerts [-k] <url> [days]")
		fmt.Println("  -k, --insecure  skip TLS certificate verification (for self-signed certs)")
		os.Exit(1)
	}

	startURL := args[0]
	days := -1

	if len(args) == 2 {
		var err error
		days, err = parseDays(args[1])
		if err != nil {
			fmt.Println("Invalid number of days:", err)
			os.Exit(1)
		}
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if *insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // user opted in via -k/--insecure
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   10 * time.Second,
		// Disable automatic redirect following so we can inspect each hop manually
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	hops, err := followRedirects(client, startURL)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	for i, hop := range hops {
		defer hop.Body.Close()

		isRedirect := hop.StatusCode >= 300 && hop.StatusCode < 400
		hopURL := sanitizeURL(hop.Request.URL.String())

		if len(hops) > 1 {
			color.Set(color.Bold, color.FgCyan)
			if isRedirect {
				location := sanitizeURL(hop.Header.Get("Location"))
				fmt.Printf("=== Hop %d: %s → %s (HTTP %d) ===\n\n", i+1, hopURL, location, hop.StatusCode)
			} else {
				fmt.Printf("=== Hop %d: %s (HTTP %d) ===\n\n", i+1, hopURL, hop.StatusCode)
			}
			color.Unset()
		}

		if hop.TLS == nil {
			fmt.Printf("No TLS on %s — skipping cert info\n\n", hopURL)
			continue
		}

		printCerts(hop, days)
	}
}

// followRedirects manually walks the redirect chain, returning one *http.Response per hop.
func followRedirects(client *http.Client, startURL string) ([]*http.Response, error) {
	var hops []*http.Response
	current := startURL

	for {
		resp, err := client.Get(current)
		if err != nil {
			return hops, fmt.Errorf("connecting to %s: %w", current, err)
		}
		hops = append(hops, resp)

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}

		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		loc, err := url.Parse(location)
		if err != nil {
			break
		}
		if !loc.IsAbs() {
			base, err := url.Parse(current)
			if err != nil {
				break
			}
			loc = base.ResolveReference(loc)
		}
		current = loc.String()

		if len(hops) > 10 {
			return hops, errors.New("too many redirects (>10)")
		}
	}

	return hops, nil
}

// printCerts prints the TLS certificate chain info from a response.
func printCerts(resp *http.Response, days int) {
	certs := resp.TLS.PeerCertificates
	validChain := true
	for i := 0; i < len(certs)-1; i++ {
		if certs[i].Issuer.CommonName != certs[i+1].Subject.CommonName {
			validChain = false
			break
		}
	}

	for _, cert := range certs {
		fmt.Printf("Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("Issuer: %s\n", cert.Issuer.CommonName)
		fmt.Printf("Valid from: %s\n", cert.NotBefore)
		fmt.Printf("Valid until: %s", cert.NotAfter)

		if days != -1 {
			daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
			if daysLeft <= days {
				color.Set(color.Bold, color.FgRed)
				fmt.Printf(" (%d days left)\n", daysLeft)
				color.Unset()
			} else {
				fmt.Println()
			}
		} else {
			fmt.Println()
		}

		fmt.Printf("Serial number: %s\n", cert.SerialNumber.String())
		fmt.Printf("DNS Names: %v\n", cert.DNSNames)
		fmt.Printf("IP Addresses: %v\n", cert.IPAddresses)
		fmt.Printf("Signature algorithm: %s\n", cert.SignatureAlgorithm.String())
		fmt.Printf("Cipher in use: %s\n", tls.CipherSuiteName(resp.TLS.CipherSuite))

		if cert.KeyUsage != 0 {
			fmt.Println("KeyUsage:")
			printKeyUsage(cert.KeyUsage)
		}

		fingerprint := sha256.Sum256(cert.Raw)
		fmt.Printf("Fingerprint (SHA-256): %s\n", hex.EncodeToString(fingerprint[:]))

		hstsHeader := resp.Header.Get("Strict-Transport-Security")
		if hstsHeader != "" {
			fmt.Println("HSTS Header:", hstsHeader)
		}

		fmt.Println("-----")
	}

	if validChain {
		color.Set(color.Bold, color.FgGreen)
		fmt.Println("Certificate chain is valid and in the correct order.")
	} else {
		color.Set(color.Bold, color.FgRed)
		fmt.Println("Certificate chain is invalid or not in the correct order.")
	}
	color.Unset()
	fmt.Println()
}

// printKeyUsage prints the key usage flags of a certificate.
func printKeyUsage(keyUsage x509.KeyUsage) {
	usageStrings := []string{
		"Digital Signature",
		"Content Commitment",
		"Key Encipherment",
		"Data Encipherment",
		"Key Agreement",
		"Certificate Signing",
		"CRL Signing",
		"Encipher Only",
		"Decipher Only",
	}

	for i, usage := range usageStrings {
		if keyUsage&(1<<i) != 0 {
			fmt.Printf("- %s\n", usage)
		}
	}
}

// validHostRE matches only legal hostname characters (letters, digits, hyphens, dots).
var validHostRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$`)

// sanitizeHost strips non-hostname characters and validates the result against a
// strict hostname pattern, returning "[invalid host]" on failure. Prevents log
// injection when printing attacker-controlled hostname values.
func sanitizeHost(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	cleaned := b.String()
	if !validHostRE.MatchString(cleaned) {
		return "[invalid host]"
	}
	return cleaned
}

// sanitizeURL strips control characters from a URL string for safe printing.
func sanitizeURL(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parseDays parses the number of days from a string.
func parseDays(daysStr string) (int, error) {
	days, err := strconv.Atoi(daysStr)
	if err != nil {
		return 0, err
	}
	if days < 0 {
		return 0, errors.New("number of days cannot be negative")
	}
	return days, nil
}
