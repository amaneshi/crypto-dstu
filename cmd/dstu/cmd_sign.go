package main

import (
	"flag"
	"fmt"
	"os"

	"crypto-dstu/ua"
)

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dstu sign [options]

Options:
  -key path[:password]    Key container (Key-6.dat, .jks, .p12, .der, .pem)
  -cert path              Certificate file (repeatable)
  -ca path                CA bundle (.p7b or directory)
  -input path             Input file (default: stdin)
  -output path            Output file (default: stdout)
  -no-tax                 Raw CMS output; omit transport header and UA_SIGN1
  -detached               Produce detached signature (content not embedded)
  -digest value           Digest: auto|gost34311|kupyna256|kupyna512 (default: auto)
  -crypt path             Recipient certificate: sign then encrypt
  -cipher value           gost28147-cfb|kalyna256-cfb|kalyna256-ofb (requires -crypt)
  -tsp url                TSP server URL (repeatable)
  -tsp-level value        Timestamp level: none|signature (default: none)
  -tsa-root path          Explicit trusted TSA certificate/CA DER (repeatable)
  -role value             Key role: personal|fop|director|stamp|other
  -email addr             Sender email for transport header
  -filename name          Attachment filename for transport header
  -include-chain value    Cert chain: none|ref|full (default: none)
`)
	}

	key := fs.String("key", "", "key container path[:password]")
	var certs multiFlag
	fs.Var(&certs, "cert", "certificate file (repeatable)")
	ca := fs.String("ca", "", "CA bundle path")
	input := fs.String("input", "-", "input file")
	output := fs.String("output", "-", "output file")
	noTax := fs.Bool("no-tax", false, "raw CMS output")
	detached := fs.Bool("detached", false, "detached signature")
	digest := fs.String("digest", "auto", "digest: auto|gost34311|kupyna256|kupyna512")
	cryptCert := fs.String("crypt", "", "recipient cert for sign+encrypt")
	cipher := fs.String("cipher", "gost28147-cfb", "encryption cipher: gost28147-cfb|kalyna256-cfb|kalyna256-ofb")
	var tspURLs multiFlag
	fs.Var(&tspURLs, "tsp", "TSP server URL (repeatable)")
	tspLevel := fs.String("tsp-level", "none", "TSP level: none|signature")
	role := fs.String("role", "", "key role")
	email := fs.String("email", "", "sender email")
	filename := fs.String("filename", "", "attachment filename")
	includeChain := fs.String("include-chain", "none", "cert chain: none|ref|full")

	var tsaRoots multiFlag
	fs.Var(&tsaRoots, "tsa-root", "explicit TSA trust certificate DER (repeatable)")
	fs.Parse(args) //nolint:errcheck // ExitOnError: never returns non-nil

	digestAlgorithm, err := parseSigningDigest(*digest)
	if err != nil {
		fatalf("sign: %v", err)
	}
	encryption, err := parseEncryptionOptions(*cipher)
	if err != nil {
		fatalf("sign: %v", err)
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "cipher" && *cryptCert == "" {
			fatalf("-cipher requires -crypt")
		}
	})
	if *tspLevel != "none" && *tspLevel != "signature" {
		fatalf("requested timestamp level is not implemented; use none or signature")
	}
	if *tspLevel == "none" && (len(tspURLs) > 0 || len(tsaRoots) > 0) {
		fatalf("timestamp options require -tsp-level signature")
	}
	if *tspLevel == "signature" && (len(tspURLs) == 0 || len(tsaRoots) == 0) {
		fatalf("signature timestamp requires -tsp and -tsa-root")
	}
	if *includeChain != "none" {
		fatalf("certificate-chain embedding is not implemented; omit -include-chain")
	}

	if *key == "" {
		fmt.Fprintln(os.Stderr, "dstu sign: -key is required")
		fs.Usage()
		os.Exit(1)
	}

	box, err := buildBox(*key, certs, *ca, *role)
	if err != nil {
		fatalf("sign setup: %v", err)
	}
	for _, u := range tspURLs {
		box.AddTSP(u)
	}

	content := mustRead(*input)

	opts := ua.SignOptions{
		Encryption:      encryption,
		DigestAlgorithm: digestAlgorithm,
		NoTax:           *noTax,
		Detached:        *detached,
		Email:           *email,
		Filename:        *filename,
	}

	if *tspLevel == "signature" {
		opts.Timestamp = &ua.TimestampSignOptions{}
		for _, path := range tsaRoots {
			opts.Timestamp.TSARoots = append(opts.Timestamp.TSARoots, mustRead(path))
		}
	}
	var result []byte
	if *cryptCert != "" {
		recipientDER := mustRead(*cryptCert)
		result, err = box.SignAndEncrypt(content, recipientDER, opts)
		if err != nil {
			fatalf("sign+encrypt: %v", err)
		}
	} else {
		result, err = box.SignDocument(content, opts)
		if err != nil {
			fatalf("sign: %v", err)
		}
	}

	mustWrite(*output, result)
}
