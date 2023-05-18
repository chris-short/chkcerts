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
	if len(os.Args) != 3 {
		fmt.Println("Please provide a URL (include https://) and the number of days")
		os.Exit(1)
	}

	url := os.Args[1]
	daysStr := os.Args[2]
	days, err := parseDays(daysStr)
	if err != nil {
		fmt.Println("Invalid number of days:", err)
		os.Exit(1)
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
	for _, cert := range certs {
		fmt.Printf("Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("Issuer: %s\n", cert.Issuer.CommonName)
		fmt.Printf("Valid from: %s\n", cert.NotBefore)
		fmt.Printf("Valid until: %s ", cert.NotAfter)

		daysLeft := int(cert.NotAfter.Sub(time.Now()).Hours()/24) + 1
		if daysLeft <= days {
			color.Red("(%d days left)", daysLeft)
		} else {
			fmt.Printf("(%d days left)", daysLeft)
		}
		fmt.Println()

		fmt.Printf("Serial number: %s\n", cert.SerialNumber.String())
		fmt.Printf("DNS Names: %v\n", cert.DNSNames)
		fmt.Printf("IP Addresses: %v\n", cert.IPAddresses)
		fmt.Printf("Signature algorithm: %s\n", cert.SignatureAlgorithm.String())
		fmt.Println("-----")
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
