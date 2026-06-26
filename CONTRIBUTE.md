# Contributing to chkcerts

Thanks for taking the time. Contributions are welcome via pull request.

## Getting started

You'll need Go installed. Clone the repo and verify things work:

```bash
git clone https://github.com/chris-short/chkcerts.git
cd chkcerts
go run chkcerts.go https://chrisshort.net
```

## Making changes

- Keep changes focused. One PR per bug fix or feature.
- Run `go vet ./...` and `go build ./...` before opening a PR.
- If you're adding behavior, update the example output in README.md to match.

## Reporting issues

Open an issue on GitHub. Include the URL you were checking and the full output (redact anything sensitive).

## Code of conduct

Be decent. This is a small tool, not a battleground.
