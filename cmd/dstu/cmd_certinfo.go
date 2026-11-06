package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/amaneshi/crypto-dstu/ua"
)

func runCertInfo(args []string) {
	fs := flag.NewFlagSet("certinfo", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: dstu certinfo [options] [cert-file]

Options:
  -cert path    Certificate file (.cer, .der, .pem) [or positional argument]
  -json         Output as JSON
`)
	}

	certPath := fs.String("cert", "", "certificate file")
	asJSON := fs.Bool("json", false, "output as JSON")

	fs.Parse(args) //nolint:errcheck // ExitOnError: never returns non-nil

	// Also accept positional argument
	if *certPath == "" && fs.NArg() > 0 {
		*certPath = fs.Arg(0)
	}
	if *certPath == "" {
		fmt.Fprintln(os.Stderr, "dstu certinfo: -cert is required")
		fs.Usage()
		os.Exit(1)
	}

	data := mustRead(*certPath)
	info, err := ua.GetCertInfo(data)
	if err != nil {
		fatalf("certinfo: %v", err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err = enc.Encode(info); err != nil {
			fatalf("certinfo json: %v", err)
		}
		return
	}

	printField := func(label, value string) {
		if value != "" {
			fmt.Printf("%-14s %s\n", label+":", value) //nolint:forbidigo // CLI output
		}
	}

	printField("Subject", info.Subject)
	printField("CommonName", info.CommonName)
	printField("Organization", info.Organization)
	printField("Title", info.Title)
	printField("EDRPOU", info.EDRPOU)
	printField("DRFO", info.DRFO)
	printField("Email", info.Email)
	printField("Serial", info.Serial)
	printField("Issuer", info.Issuer)
	fmt.Printf("%-14s %s\n", "NotBefore:", info.NotBefore.UTC().Format(time.RFC3339)) //nolint:forbidigo // CLI output
	fmt.Printf("%-14s %s\n", "NotAfter:", info.NotAfter.UTC().Format(time.RFC3339))   //nolint:forbidigo // CLI output
	printField("Role", info.Role)
	printField("Algorithm", info.Algorithm)
	printField("Curve", info.CurveName)
	printField("KeyID", info.KeyID)
	fmt.Printf("%-14s %v\n", "IsCA:", info.IsCA) //nolint:forbidigo // CLI output
}
