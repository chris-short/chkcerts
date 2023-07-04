![GitHub](https://img.shields.io/github/license/chris-short/chkcerts)
[![release](https://github.com/chris-short/chkcerts/actions/workflows/release.yaml/badge.svg)](https://github.com/chris-short/chkcerts/actions/workflows/release.yaml)
![GitHub release (with filter)](https://img.shields.io/github/v/release/chris-short/chkcerts)
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

	Subject: *.chrisshort.net
	Issuer: R3
	Valid from: 2023-04-25 02:30:44 +0000 UTC
	Valid until: 2023-07-24 02:30:43 +0000 UTC
	Serial number: 403588798235445259445834570997555816122123
	DNS Names: [*.chrisshort.net chrisshort.net]
	IP Addresses: []
	Signature algorithm: SHA256-RSA
	-----
	Subject: R3
	Issuer: ISRG Root X1
	Valid from: 2020-09-04 00:00:00 +0000 UTC
	Valid until: 2025-09-15 16:00:00 +0000 UTC
	Serial number: 192961496339968674994309121183282847578
	DNS Names: []
	IP Addresses: []
	Signature algorithm: SHA256-RSA
	-----
	Subject: ISRG Root X1
	Issuer: DST Root CA X3
	Valid from: 2021-01-20 19:14:03 +0000 UTC
	Valid until: 2024-09-30 18:14:03 +0000 UTC
	Serial number: 85078200265644417569109389142156118711
	DNS Names: []
	IP Addresses: []
	Signature algorithm: SHA256-RSA
	-----
	Certificate chain is valid and in the correct order.

### Example Output with Days

	Subject: *.chrisshort.net
	Issuer: R3
	Valid from: 2023-04-25 02:30:44 +0000 UTC
	Valid until: 2023-07-24 02:30:43 +0000 UTC (66 days left)
	Serial number: 403588798235445259445834570997555816122123
	DNS Names: [*.chrisshort.net chrisshort.net]
	IP Addresses: []
	Signature algorithm: SHA256-RSA
	-----
	Subject: R3
	Issuer: ISRG Root X1
	Valid from: 2020-09-04 00:00:00 +0000 UTC
	Valid until: 2025-09-15 16:00:00 +0000 UTC
	Serial number: 192961496339968674994309121183282847578
	DNS Names: []
	IP Addresses: []
	Signature algorithm: SHA256-RSA
	-----
	Subject: ISRG Root X1
	Issuer: DST Root CA X3
	Valid from: 2021-01-20 19:14:03 +0000 UTC
	Valid until: 2024-09-30 18:14:03 +0000 UTC
	Serial number: 85078200265644417569109389142156118711
	DNS Names: []
	IP Addresses: []
	Signature algorithm: SHA256-RSA
	-----
	Certificate chain is valid and in the correct order.

## About

There's a general lack of understanding of how TLS works, the certificate chains used, or cryptography in general. Creating command line tools to help show folks how things work can't hurt, right?
