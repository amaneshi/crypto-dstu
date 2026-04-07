package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dstu decrypt [options]

Options:
  -key path[:password]    Key container
  -ca path                CA bundle for chain verification
  -input path             Input file (default: stdin)
  -output path            Output file (default: stdout)
  -role value             Key role: personal|fop|director|stamp|other
  -v                      Print signer information to stderr
`)
	}

	key := fs.String("key", "", "key container path[:password]")
	ca := fs.String("ca", "", "CA bundle path")
	input := fs.String("input", "-", "input file")
	output := fs.String("output", "-", "output file")
	role := fs.String("role", "", "key role")
	verbose := fs.Bool("v", false, "print signer info to stderr")

	fs.Parse(args) //nolint:errcheck // ExitOnError: never returns non-nil

	if *key == "" {
		fmt.Fprintln(os.Stderr, "dstu decrypt: -key is required")
		fs.Usage()
		os.Exit(1)
	}

	box, err := buildBox(*key, nil, *ca, *role)
	if err != nil {
		fatalf("decrypt setup: %v", err)
	}

	data := mustRead(*input)

	// Try unsign first (handles transport container + raw CMS).
	result, err := box.UnsignDocument(data)
	if err != nil {
		// Try decrypt-then-unsign (EnvelopedData wrapping SignedData).
		plain, err2 := box.DecryptDocument(data)
		if err2 != nil {
			fatalf("decrypt: %v", err2)
		}
		result, err = box.UnsignDocument(plain)
		if err != nil {
			fatalf("unsign after decrypt: %v", err)
		}
	}

	if *verbose {
		for _, s := range result.Signers {
			name := "<unknown>"
			edrpou := ""
			if s.CertInfo != nil {
				name = s.CertInfo.CommonName
				edrpou = s.CertInfo.EDRPOU
			}
			ts := s.SigningTime
			if ts.IsZero() {
				ts = time.Time{}
			}
			fmt.Fprintf(os.Stderr, "signer: %s", name)
			if edrpou != "" {
				fmt.Fprintf(os.Stderr, " (EDRPOU: %s)", edrpou)
			}
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "  valid=%v", s.Valid)
			if !ts.IsZero() {
				fmt.Fprintf(os.Stderr, "  time=%s", ts.Format(time.RFC3339))
			}
			fmt.Fprintf(os.Stderr, "\n")
			if s.Error != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", s.Error)
			}
		}
		if result.Header != nil {
			fmt.Fprintf(os.Stderr, "transport header: filename=%s from=%s\n",
				result.Header.Filename, result.Header.SndEmail)
		}
	}

	mustWrite(*output, result.Content)
}
