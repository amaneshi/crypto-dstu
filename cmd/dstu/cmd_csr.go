package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"crypto-dstu/internal/csr"
	"crypto-dstu/internal/keystore"
	"crypto-dstu/internal/oid"
	"crypto-dstu/pkg/dstu4145"
)

func runCSR(args []string) {
	fs := flag.NewFlagSet("csr", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dstu csr [options]

Generates a DER-encoded PKCS#10 Certificate Signing Request (RFC 2986)
using a DSTU 4145 private key.  If -key is omitted a fresh key on
DSTU_PB_257 (or -curve) is generated and used for this CSR only.

Options:
  -key path[:password]    Existing key container (optional)
  -curve name             Curve for fresh key generation (default: DSTU_PB_257)
  -cn value               Common name (Subject CN)
  -org value              Organisation (Subject O)
  -country value          Country code (Subject C, 2 chars)
  -edrpou value           EDRPOU code (Ukrainian organisation identifier)
  -drfo value             DRFO code (Ukrainian personal tax number)
  -output path            Output DER file (default: stdout)
`)
	}

	keyFlag := fs.String("key", "", "key container path[:password]")
	curveName := fs.String("curve", "DSTU_PB_257", "curve for key generation")
	cnFlag := fs.String("cn", "", "common name")
	orgFlag := fs.String("org", "", "organisation")
	countryFlag := fs.String("country", "", "country code")
	edrpouFlag := fs.String("edrpou", "", "EDRPOU code")
	drfoFlag := fs.String("drfo", "", "DRFO code")
	output := fs.String("output", "-", "output DER file")

	fs.Parse(args) //nolint:errcheck // ExitOnError: never returns non-nil

	if *cnFlag == "" && *edrpouFlag == "" {
		fmt.Fprintln(os.Stderr, "dstu csr: at least -cn or -edrpou is required")
		fs.Usage()
		os.Exit(1)
	}

	// Obtain private key: from container or freshly generated.
	var priv *dstu4145.PrivateKey
	if *keyFlag != "" {
		parts := strings.SplitN(*keyFlag, ":", 2)
		path, password := parts[0], ""
		if len(parts) == 2 {
			password = parts[1]
		}
		data, err := os.ReadFile(path)
		if err != nil {
			fatalf("csr: read key: %v", err)
		}
		result, err := keystore.Parse(data, password)
		if err != nil {
			result, err = keystore.ParseJKSWithPassword(data, password)
			if err != nil {
				fatalf("csr: load key: %v", err)
			}
		}
		if len(result.Keys) == 0 {
			fatalf("csr: no private key found in %s", path)
		}
		priv = result.Keys[0]
	} else {
		params := dstu4145.ParamsByName(*curveName)
		if params == nil {
			fatalf("csr: unknown curve %q; valid examples: DSTU_PB_257, DSTU_PB_431", *curveName)
		}
		var err error
		priv, err = dstu4145.GenerateKey(params.Curve)
		if err != nil {
			fatalf("csr: generate key: %v", err)
		}
	}

	// Build subject attributes.
	var subject []csr.AttributeTypeAndValue
	if *cnFlag != "" {
		subject = append(subject, csr.AttributeTypeAndValue{Type: oid.OIDCommonName, Value: *cnFlag})
	}
	if *orgFlag != "" {
		subject = append(subject, csr.AttributeTypeAndValue{Type: oid.OIDOrganization, Value: *orgFlag})
	}
	if *countryFlag != "" {
		subject = append(subject, csr.AttributeTypeAndValue{Type: oid.OIDCountry, Value: *countryFlag})
	}
	if *edrpouFlag != "" {
		subject = append(subject, csr.AttributeTypeAndValue{Type: oid.EDRPOU, Value: *edrpouFlag})
	}
	if *drfoFlag != "" {
		subject = append(subject, csr.AttributeTypeAndValue{Type: oid.DRFO, Value: *drfoFlag})
	}

	der, err := csr.Create(&csr.Request{Subject: subject}, priv)
	if err != nil {
		fatalf("csr: %v", err)
	}

	mustWrite(*output, der)
}
