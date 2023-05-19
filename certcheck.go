// Usage
//
// go run certcheck.go https://chrisshort.net
//
// go run certcheck.go https://chrisshort.net 30
//

package main

import (
	"crypto/tls"
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

	url := os.Args[1]
	var days int = -1 // Default value if days argument is not provided

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
			InsecureSkipVerify: true, // allow self-signed certificates
		},
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error connecting to %s: %s\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

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

		if days != -1 {
			daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
			if daysLeft <= days {
				color.Set(color.Bold, color.FgRed)
				fmt.Printf(" (%d days left)", daysLeft)
				color.Unset()
			}
		}

		fmt.Println()
		fmt.Printf("Serial number: %s\n", cert.SerialNumber.String())
		fmt.Printf("DNS Names: %v\n", cert.DNSNames)
		fmt.Printf("IP Addresses: %v\n", cert.IPAddresses)
		fmt.Printf("Signature algorithm: %s\n", cert.SignatureAlgorithm.String())
		fmt.Println("-----")
	}

	if validChain {
		color.Set(color.Bold, color.FgGreen)
		fmt.Println("Certificate chain is valid and in the correct order.")
	} else {
		color.Set(color.Bold, color.FgRed)
		fmt.Println("Certificate chain is invalid or not in the correct order.")
	}
}

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
