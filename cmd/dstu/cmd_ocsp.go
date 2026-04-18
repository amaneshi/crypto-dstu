package main

import (
	"flag"
	"fmt"
	"os"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/keystore"
	"crypto-dstu/internal/ocsp"
)

func runOCSP(args []string) {
	fs := flag.NewFlagSet("ocsp", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dstu ocsp [options]

Checks the revocation status of a certificate using OCSP (RFC 6960).
The OCSP responder URL is taken from the certificate's AIA extension
unless -url is specified.

Options:
  -cert path     Certificate to check (required)
  -issuer path   Issuer certificate (required)
  -url url       Override OCSP responder URL
`)
	}

	certPath := fs.String("cert", "", "certificate to check")
	issuerPath := fs.String("issuer", "", "issuer certificate")
	urlFlag := fs.String("url", "", "OCSP responder URL override")

	fs.Parse(args) //nolint:errcheck // ExitOnError: never returns non-nil

	if *certPath == "" {
		fmt.Fprintln(os.Stderr, "dstu ocsp: -cert is required")
		fs.Usage()
		os.Exit(1)
	}
	if *issuerPath == "" {
		fmt.Fprintln(os.Stderr, "dstu ocsp: -issuer is required")
		fs.Usage()
		os.Exit(1)
	}

	subjectDER := keystore.MaybePEM(mustRead(*certPath))
	issuerDER := keystore.MaybePEM(mustRead(*issuerPath))

	subjectCert, err := cert.ParseCertificate(subjectDER)
	if err != nil {
		fatalf("ocsp: parse -cert: %v", err)
	}
	issuerCert, err := cert.ParseCertificate(issuerDER)
	if err != nil {
		fatalf("ocsp: parse -issuer: %v", err)
	}

	client := &ocsp.Client{URL: *urlFlag}
	resp, err := client.Check(subjectCert, issuerCert)
	if err != nil {
		fatalf("ocsp: %v", err)
	}

	if resp.Status != 0 {
		fatalf("ocsp: responder returned non-successful status %d", resp.Status)
	}

	if len(resp.Responses) == 0 {
		fatalf("ocsp: response contained no SingleResponse entries")
	}

	sr := resp.Responses[0]
	switch sr.Status {
	case ocsp.Good:
		fmt.Println("status: good") //nolint:forbidigo // CLI output
	case ocsp.Revoked:
		if sr.RevocationTime.IsZero() {
			fmt.Println("status: revoked") //nolint:forbidigo // CLI output
		} else {
			ts := sr.RevocationTime.UTC().Format("2006-01-02T15:04:05Z")
			fmt.Printf("status: revoked (at %s)\n", ts) //nolint:forbidigo // CLI output
		}
		os.Exit(2)
	case ocsp.Unknown:
		fmt.Println("status: unknown") //nolint:forbidigo // CLI output
		os.Exit(3)
	}

	fmt.Printf("thisUpdate: %s\n", sr.ThisUpdate.UTC().Format("2006-01-02T15:04:05Z")) //nolint:forbidigo // CLI output
	if !sr.NextUpdate.IsZero() {
		nu := sr.NextUpdate.UTC().Format("2006-01-02T15:04:05Z")
		fmt.Printf("nextUpdate: %s\n", nu) //nolint:forbidigo // CLI output
	}
}
