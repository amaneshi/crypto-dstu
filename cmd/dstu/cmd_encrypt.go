package main

import (
	"flag"
	"fmt"
	"os"
)

func runEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dstu encrypt [options]

Options:
  -key path[:password]    Sender key container
  -cert path              Sender certificate (repeatable)
  -crypt path             Recipient certificate (required)
  -cipher value           Cipher: gost28147-cfb|kalyna256-cfb|kalyna256-ofb
  -input path             Input file (default: stdin)
  -output path            Output file (default: stdout)
`)
	}

	key := fs.String("key", "", "sender key container path[:password]")
	var certs multiFlag
	fs.Var(&certs, "cert", "sender certificate (repeatable)")
	cryptCert := fs.String("crypt", "", "recipient certificate")
	cipher := fs.String("cipher", "gost28147-cfb", "content encryption profile")
	input := fs.String("input", "-", "input file")
	output := fs.String("output", "-", "output file")

	fs.Parse(args) //nolint:errcheck // ExitOnError: never returns non-nil
	options, err := parseEncryptionOptions(*cipher)
	if err != nil {
		fatalf("encrypt: %v", err)
	}

	if *key == "" {
		fmt.Fprintln(os.Stderr, "dstu encrypt: -key is required")
		fs.Usage()
		os.Exit(1)
	}
	if *cryptCert == "" {
		fmt.Fprintln(os.Stderr, "dstu encrypt: -crypt (recipient certificate) is required")
		fs.Usage()
		os.Exit(1)
	}

	box, err := buildBox(*key, certs, "", "")
	if err != nil {
		fatalf("encrypt setup: %v", err)
	}

	recipientDER := mustRead(*cryptCert)
	content := mustRead(*input)

	result, err := box.EncryptDocumentWithOptions(content, recipientDER, options)
	if err != nil {
		fatalf("encrypt: %v", err)
	}

	mustWrite(*output, result)
}
