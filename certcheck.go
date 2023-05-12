// Usage:
//
//   certcheck https://www.example.com
//
// Output:
//
//   Subject: www.example.com
//   Issuer: Google Inc
//   Valid from: 2020-01-01 00:00:00 +0000 UTC
//   Valid until: 2030-01-01 00:00:00 +0000 UTC
//   Serial number: 46d1c9e7a9e9f9e4
//   DNS Names: [www.example.com]
//   IP Addresses: []
//   Signature algorithm: sha256WithRSAEncryption

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Please provide a URL as an argument.")
		os.Exit(1)
	}

	url := os.Args[1]

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
		fmt.Printf("Valid until: %s\n", cert.NotAfter)
		fmt.Printf("Serial number: %s\n", cert.SerialNumber.String())
		fmt.Printf("DNS Names: %v\n", cert.DNSNames)
		fmt.Printf("IP Addresses: %v\n", cert.IPAddresses)
		fmt.Printf("Signature algorithm: %s\n", cert.SignatureAlgorithm.String())
		fmt.Println("-----")
	}
}
