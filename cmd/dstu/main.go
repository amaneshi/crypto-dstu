// Command dstu is a CLI tool for Ukrainian DSTU cryptographic operations:
// sign, decrypt/verify, encrypt, certinfo, and unprotect.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "sign":
		runSign(os.Args[2:])
	case "decrypt", "unwrap":
		runDecrypt(os.Args[2:])
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "certinfo":
		runCertInfo(os.Args[2:])
	case "csr":
		runCSR(os.Args[2:])
	case "ocsp":
		runOCSP(os.Args[2:])
	case "unprotect":
		runUnprotect(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "dstu: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: dstu <command> [options]

commands:
  sign        Sign a document (optionally encrypt for recipient)
  decrypt     Decrypt and/or verify an incoming document
  encrypt     Encrypt a document for a recipient
  certinfo    Print certificate information
  csr         Generate a PKCS#10 Certificate Signing Request
  ocsp        Check certificate revocation status via OCSP
  unprotect   Remove password protection from a key container

Run "dstu <command> -h" for command-specific help.
`)
}
