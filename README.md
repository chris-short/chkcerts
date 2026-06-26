![GitHub](https://img.shields.io/github/license/chris-short/chkcerts)  
![GitHub all releases](https://img.shields.io/github/downloads/chris-short/chkcerts/total)
![GitHub repo size](https://img.shields.io/github/repo-size/chris-short/chkcerts)
![GitHub contributors](https://img.shields.io/github/contributors/chris-short/chkcerts)

![Twitter Follow](https://img.shields.io/twitter/follow/ChrisShort)




# chkcerts

A Go program to display certificate chains and validate their order in the same vein as [ssl-tester](https://github.com/chris-short/ssl-tester) but more flexible.

## Usage

	chkcerts https://chrisshort.net

	chkcerts https://chrisshort.net 90

### Example Output (no days)

	Subject: chrisshort.net
	Issuer: E7
	Valid from: 2026-05-25 00:29:00 +0000 UTC
	Valid until: 2026-08-23 00:28:59 +0000 UTC
	Serial number: 455967643380891922849939626027783376065774
	DNS Names: [*.chrisshort.me *.chrisshort.us chrisshort.me chrisshort.net chrisshort.us www.chrisshort.net]
	IP Addresses: []
	Signature algorithm: ECDSA-SHA384
	Cipher in use: TLS_AES_128_GCM_SHA256
	KeyUsage:
	- Digital Signature
	Fingerprint (SHA-256): 81cd2cce6caf805ec597523569b7389ffef006ac49e2dc83e43a5e1caa93ed2e
	HSTS Header: max-age=63072000; includeSubDomains; preload
	-----
	Subject: E7
	Issuer: ISRG Root X1
	Valid from: 2024-03-13 00:00:00 +0000 UTC
	Valid until: 2027-03-12 23:59:59 +0000 UTC
	Serial number: 226581164312556911225609404641709439649
	DNS Names: []
	IP Addresses: []
	Signature algorithm: SHA256-RSA
	Cipher in use: TLS_AES_128_GCM_SHA256
	KeyUsage:
	- Digital Signature
	- Certificate Signing
	- CRL Signing
	Fingerprint (SHA-256): aeb1fd7410e83bc96f5da3c6a7c2c1bb836d1fa5cb86e708515890e428a8770b
	HSTS Header: max-age=63072000; includeSubDomains; preload
	-----
	Certificate chain is valid and in the correct order.

### Example Output with Days

	Subject: chrisshort.net
	Issuer: E7
	Valid from: 2026-05-25 00:29:00 +0000 UTC
	Valid until: 2026-08-23 00:28:59 +0000 UTC (57 days left)
	Serial number: 455967643380891922849939626027783376065774
	DNS Names: [*.chrisshort.me *.chrisshort.us chrisshort.me chrisshort.net chrisshort.us www.chrisshort.net]
	IP Addresses: []
	Signature algorithm: ECDSA-SHA384
	Cipher in use: TLS_AES_128_GCM_SHA256
	KeyUsage:
	- Digital Signature
	Fingerprint (SHA-256): 81cd2cce6caf805ec597523569b7389ffef006ac49e2dc83e43a5e1caa93ed2e
	HSTS Header: max-age=63072000; includeSubDomains; preload
	-----
	Certificate chain is valid and in the correct order.

### Example Output with Redirects

When a URL redirects, each hop in the chain is reported separately:

	=== Hop 1: https://commandlineheroes.com → https://www.redhat.com/en/command-line-heroes (HTTP 301) ===

	Subject: commandlineheroes.com
	Issuer: YE1
	...
	Certificate chain is valid and in the correct order.

	=== Hop 2: https://www.redhat.com/en/command-line-heroes (HTTP 200) ===

	Subject: www.redhat.com
	Issuer: DigiCert EV RSA CA G2
	...
	Certificate chain is valid and in the correct order.

## About

There's a general lack of understanding of how TLS works, the certificate chains used, or cryptography in general. Creating command line tools to help show folks how things work can't hurt, right?
