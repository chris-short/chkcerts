// Usage
//
// go run certcheck.go https://chrisshort.net
//
// go run certcheck.go https://chrisshort.net
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"errors"

	"github.com/fatih/color"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Println("Please provide a URL (include https://) and an optional number of days")
		os.Exit(1)
	}

	// Parse the URL and number of days
	url := os.Args[1]
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

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			// This is required to allow self-signed certificates
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{Transport: tr}

	// Check if the URL is valid
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error connecting to %s: %s\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Check if the response was successful
	certs := resp.TLS.PeerCertificates
	var validChain bool = true
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

		// Check if the certificate is expired
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

		// Obtain the cipher information
		state := resp.TLS
		if state != nil {
			fmt.Printf("Cipher in use: %s\n", tls.CipherSuiteName(state.CipherSuite))
		}

		// Print KeyUsage information if available
		if cert.KeyUsage != 0 {
			fmt.Println("KeyUsage:")
			printKeyUsage(cert.KeyUsage)
		}

		// Calculate and print the SHA-256 fingerprint
		fingerprint := sha256.Sum256(cert.Raw)
		fmt.Printf("Fingerprint (SHA-256): %s\n", hex.EncodeToString(fingerprint[:]))

		// Check if the HSTS header is present
		hstsHeader := resp.Header.Get("Strict-Transport-Security")
		if hstsHeader != "" {
			fmt.Println("HSTS Header:", hstsHeader)
		}

		fmt.Println("-----")
	}

	// Print the validity of the certificate chain
	if validChain {
		color.Set(color.Bold, color.FgGreen)
		fmt.Println("Certificate chain is valid and in the correct order.")
	} else {
		color.Set(color.Bold, color.FgRed)
		fmt.Println("Certificate chain is invalid or not in the correct order.")
	}
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
