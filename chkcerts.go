// Usage
//
// go run chkcerts.go https://chrisshort.net
//
// go run chkcerts.go https://chrisshort.net 90
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"errors"

	"github.com/fatih/color"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Println("Please provide a URL (include https://) and an optional number of days to highlight expiring certificates")
		os.Exit(1)
	}

	// Parse the URL and number of days
	rawURL := os.Args[1]
	var days int = -1 // Default value if days argument is not provided

	// Check if the number of days argument is provided
	if len(os.Args) == 3 {
		daysStr := os.Args[2]
		var err error
		days, err = parseDays(daysStr)
		if err != nil {
			fmt.Println("Invalid number of days:", err)
			os.Exit(1)
		}
	}

	// Collect all unique hosts from the redirect chain, preserving order
	hosts, finalResp, err := collectRedirectChain(rawURL)
	if err != nil {
		fmt.Printf("Error connecting to %s: %s\n", rawURL, err)
		os.Exit(1)
	}
	defer finalResp.Body.Close()

	hstsHeader := finalResp.Header.Get("Strict-Transport-Security")

	for i, host := range hosts {
		if len(hosts) > 1 {
			if i == 0 {
				fmt.Printf("=== Certificate for %s (original) ===\n", host)
			} else {
				fmt.Printf("=== Certificate for %s (redirect) ===\n", host)
			}
		}

		certs, tlsState, err := getCerts(host)
		if err != nil {
			fmt.Printf("Error getting certificate for %s: %s\n", host, err)
			fmt.Println("-----")
			continue
		}

		var validChain bool = true
		for j := 0; j < len(certs)-1; j++ {
			if certs[j].Issuer.CommonName != certs[j+1].Subject.CommonName {
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

			if tlsState != nil {
				fmt.Printf("Cipher in use: %s\n", tls.CipherSuiteName(tlsState.CipherSuite))
			}

			if cert.KeyUsage != 0 {
				fmt.Println("KeyUsage:")
				printKeyUsage(cert.KeyUsage)
			}

			fingerprint := sha256.Sum256(cert.Raw)
			fmt.Printf("Fingerprint (SHA-256): %s\n", hex.EncodeToString(fingerprint[:]))

			// Only print HSTS for the final destination
			if i == len(hosts)-1 && hstsHeader != "" {
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

		if i < len(hosts)-1 {
			fmt.Println()
		}
	}
}

// collectRedirectChain follows the redirect chain from the given URL and returns
// an ordered, deduplicated list of unique hostnames encountered, plus the final response.
func collectRedirectChain(rawURL string) ([]string, *http.Response, error) {
	var chain []string
	seen := make(map[string]bool)

	addHost := func(u string) {
		parsed, err := url.Parse(u)
		if err != nil {
			return
		}
		host := parsed.Hostname()
		if !seen[host] {
			seen[host] = true
			chain = append(chain, host)
		}
	}

	addHost(rawURL)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// This is required to allow self-signed certificates to be checked
			// It's my opinion that this is a bad idea, but it's the only way to accommodate some users
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			addHost(req.URL.String())
			return nil
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, nil, err
	}

	return chain, resp, nil
}

// getCerts dials the given hostname directly over TLS and returns its peer certificates
// along with the TLS connection state.
func getCerts(host string) ([]*x509.Certificate, *tls.ConnectionState, error) {
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return state.PeerCertificates, &state, nil
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

	// Print the key usage flags of a certificate.
	for i, usage := range usageStrings {
		if keyUsage&(1<<i) != 0 {
			fmt.Printf("- %s\n", usage)
		}
	}
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
