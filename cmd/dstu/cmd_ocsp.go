package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/ocsp"
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
  -issuer path   Explicitly trusted issuer certificate (required)
  -response path Saved DER OCSP response instead of a network request
  -responder-crl path Full DER CRL for delegated responder (repeatable)
  -url url       Override OCSP responder URL
`)
	}

	certPath := fs.String("cert", "", "certificate to check")
	issuerPath := fs.String("issuer", "", "issuer certificate")
	urlFlag := fs.String("url", "", "OCSP responder URL override")
	responsePath := fs.String("response", "", "saved DER OCSP response")

	var crlPaths multiFlag
	fs.Var(&crlPaths, "responder-crl", "full responder CRL (repeatable)")
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

	var resp *ocsp.Response
	if *responsePath != "" {
		resp, err = ocsp.ParseResponse(mustRead(*responsePath))
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		resp, err = (&ocsp.Client{URL: *urlFlag}).CheckContext(ctx, subjectCert, issuerCert)
	}
	if err != nil {
		fatalf("ocsp: %v", err)
	}
	var crls [][]byte
	for _, path := range crlPaths {
		crls = append(crls, mustRead(path))
	}
	status, err := resp.CheckWithPolicy(subjectCert, issuerCert, ocsp.ValidationPolicy{Time: time.Now(), MaxAge: 24 * time.Hour, ClockSkew: 5 * time.Minute, ResponderCRLs: crls})
	if errors.Is(err, ocsp.ErrRevoked) {
		fmt.Println("status: revoked")
		os.Exit(2)
	}
	if errors.Is(err, ocsp.ErrUnknown) {
		fmt.Println("status: unknown")
		os.Exit(3)
	}
	if err != nil || status != ocsp.Good {
		fatalf("ocsp: status was not authenticated: %v", err)
	}
	fmt.Println("status: good")
	fmt.Printf("producedAt: %s\n", resp.ProducedAt.UTC().Format(time.RFC3339))
}
