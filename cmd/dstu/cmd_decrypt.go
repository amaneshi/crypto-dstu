package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/amaneshi/crypto-dstu/ua"
)

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dstu decrypt [options]

Options:
  -key path[:password]    Key container
  -cert path              Recipient or sender certificate file (repeatable)
  -ca path                CA bundle for chain verification
  -require-ocsp           Require fresh authenticated OCSP for the certificate path
  -ocsp-response path     Saved DER OCSP response (repeatable; enables required OCSP)
  -responder-crl path     Full DER CRL for delegated responder (repeatable)
  -require-timestamp      Require a verified signature timestamp per signer
  -tsa-root path          Explicit trusted TSA certificate/CA DER file (repeatable)
  -input path             Input file (default: stdin)
  -output path            Output file (default: stdout)
  -role value             Key role: personal|fop|director|stamp|other
  -v                      Print signer information to stderr
`)
	}

	key := fs.String("key", "", "key container path[:password]")
	var certs multiFlag
	fs.Var(&certs, "cert", "recipient or sender certificate file (repeatable)")
	ca := fs.String("ca", "", "CA bundle path")
	input := fs.String("input", "-", "input file")
	output := fs.String("output", "-", "output file")
	role := fs.String("role", "", "key role")
	verbose := fs.Bool("v", false, "print signer info to stderr")
	requireOCSP := fs.Bool("require-ocsp", false, "require authenticated OCSP evidence")
	var responses multiFlag
	fs.Var(&responses, "ocsp-response", "saved OCSP response (repeatable)")

	var crlPaths multiFlag
	fs.Var(&crlPaths, "responder-crl", "full responder CRL (repeatable)")
	requireTimestamp := fs.Bool("require-timestamp", false, "require verified signature timestamps")
	var tsaRoots multiFlag
	fs.Var(&tsaRoots, "tsa-root", "explicit TSA trust certificate DER (repeatable; verifies present timestamps)")
	fs.Parse(args) //nolint:errcheck // ExitOnError: never returns non-nil

	if *key == "" {
		fmt.Fprintln(os.Stderr, "dstu decrypt: -key is required")
		fs.Usage()
		os.Exit(1)
	}

	box, err := buildBox(*key, certs, *ca, *role)
	if err != nil {
		fatalf("decrypt setup: %v", err)
	}

	data := mustRead(*input)
	options := ua.VerificationOptions{}
	if *requireOCSP || len(responses) > 0 || len(crlPaths) > 0 {
		options.Revocation = ua.RevocationRequireOCSP
	}
	for _, path := range responses {
		options.OCSPResponses = append(options.OCSPResponses, mustRead(path))
	}
	for _, path := range crlPaths {
		options.ResponderCRLs = append(options.ResponderCRLs, mustRead(path))
	}
	if *requireTimestamp {
		options.TimestampPolicy = ua.TimestampRequireSignature
	} else if len(tsaRoots) > 0 {
		options.TimestampPolicy = ua.TimestampVerifyIfPresent
	}
	for _, path := range tsaRoots {
		options.TSARoots = append(options.TSARoots, mustRead(path))
	}
	ctx := context.Background()

	// Try unsign first (handles transport container + raw CMS).
	result, err := box.UnsignDocumentWithOptions(ctx, data, nil, options)
	if err != nil {
		if result != nil {
			fatalf("verify: %v", err)
		}
		// Try decrypt-then-unsign (EnvelopedData wrapping SignedData).
		plain, err2 := box.DecryptDocument(data)
		if err2 != nil {
			fatalf("decrypt: %v", err2)
		}
		result, err = box.UnsignDocumentWithOptions(ctx, plain, nil, options)
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
			fmt.Fprintf(os.Stderr, "  valid=%v revocation=%s", s.Valid, s.RevocationStatus)
			if !ts.IsZero() {
				fmt.Fprintf(os.Stderr, "  time=%s", ts.Format(time.RFC3339))
			}
			fmt.Fprintf(os.Stderr, "\n")
			if s.Error != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", s.Error)
			}
		}
		for _, ts := range result.Timestamps {
			fmt.Fprintf(os.Stderr, "timestamp: signer=%d type=%s valid=%v revocation=%s time=%s\n", ts.SignerIndex, ts.Type, ts.Valid, ts.RevocationStatus, ts.Time.UTC().Format(time.RFC3339))
		}
		if result.Header != nil {
			fmt.Fprintf(os.Stderr, "transport header: filename=%s from=%s\n",
				result.Header.Filename, result.Header.SndEmail)
		}
	}

	if len(result.Signers) == 0 {
		fatalf("decrypt: no verified signers")
	}
	for _, signer := range result.Signers {
		if !signer.Valid || signer.Error != nil {
			fatalf("decrypt: invalid signature")
		}
	}
	mustWrite(*output, result.Content)
}
