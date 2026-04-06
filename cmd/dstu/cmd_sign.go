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
  -crypt path             Recipient certificate: sign then encrypt
  -tsp url                TSP server URL (repeatable)
  -tsp-level value        Timestamp level: none|signature|content|all (default: none)
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
	cryptCert := fs.String("crypt", "", "recipient cert for sign+encrypt")
	var tspURLs multiFlag
	fs.Var(&tspURLs, "tsp", "TSP server URL (repeatable)")
	tspLevel := fs.String("tsp-level", "none", "TSP level: none|signature|content|all")
	role := fs.String("role", "", "key role")
	email := fs.String("email", "", "sender email")
	filename := fs.String("filename", "", "attachment filename")
	includeChain := fs.String("include-chain", "none", "cert chain: none|ref|full")

	fs.Parse(args)

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
		NoTax:    *noTax,
		Detached: *detached,
		Email:    *email,
		Filename: *filename,
	}
	_ = *tspLevel    // TSP stamping is a future extension on top of existing ua.SignOptions
	_ = *includeChain // CAdES-C/X chain embedding is a future extension

	var result []byte
	if *cryptCert != "" {
		recipientDER := mustRead(*cryptCert)
		result, err = box.SignAndEncryptDER(content, recipientDER, opts)
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
