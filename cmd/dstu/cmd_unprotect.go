package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/amaneshi/crypto-dstu/ua"
)

func runUnprotect(args []string) {
	fs := flag.NewFlagSet("unprotect", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dstu unprotect [options]

Removes password protection from a key container and writes
the raw private key in PEM (default) or DER format.

Options:
  -key path:password    Encrypted key container with password (required)
  -output path          Output file (default: stdout)
  -der                  Output DER instead of PEM
`)
	}

	keyFlag := fs.String("key", "", "key container path:password")
	output := fs.String("output", "-", "output file")
	asDER := fs.Bool("der", false, "output DER instead of PEM")

	fs.Parse(args) //nolint:errcheck // ExitOnError: never returns non-nil

	if *keyFlag == "" {
		fmt.Fprintln(os.Stderr, "dstu unprotect: -key path:password is required")
		fs.Usage()
		os.Exit(1)
	}

	parts := strings.SplitN(*keyFlag, ":", 2)
	if len(parts) != 2 {
		fatalf("unprotect: -key must be path:password (colon-separated)")
	}
	path := parts[0]
	password := parts[1]

	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("unprotect: read %s: %v", path, err)
	}

	format := "pem"
	if *asDER {
		format = "der"
	}

	out, err := ua.UnprotectKey(data, password, format)
	if err != nil {
		fatalf("unprotect: %v", err)
	}

	mustWrite(*output, out)
}
