package main

import (
	"encoding/asn1"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"crypto-dstu/internal/oid"
	"crypto-dstu/ua"
)

func parseSigningDigest(value string) (asn1.ObjectIdentifier, error) {
	switch value {
	case "auto":
		return nil, nil
	case "gost34311":
		return slices.Clone(oid.GOST34311), nil
	case "kupyna256":
		return slices.Clone(oid.Kupyna256), nil
	case "kupyna512":
		return slices.Clone(oid.Kupyna512), nil
	default:
		return nil, fmt.Errorf("unknown digest %q; use auto, gost34311, kupyna256 or kupyna512", value)
	}
}

func parseEncryptionOptions(value string) (ua.EncryptionOptions, error) {
	switch ua.EncryptionAlgorithm(value) {
	case ua.EncryptionGOST28147CFB, ua.EncryptionKalyna256CFB, ua.EncryptionKalyna256OFB:
		return ua.EncryptionOptions{Algorithm: ua.EncryptionAlgorithm(value)}, nil
	default:
		return ua.EncryptionOptions{}, fmt.Errorf("unknown cipher %q; use gost28147-cfb, kalyna256-cfb or kalyna256-ofb", value)
	}
}

// multiFlag implements [flag.Value] for flags that may be repeated (e.g. -cert, -tsp).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// buildBox constructs a ua.Box from the common flag values.
func buildBox(keyFlag string, certFlags []string, caPath string, role string) (*ua.Box, error) {
	box := ua.NewBox()

	if keyFlag != "" {
		path, password := splitKeyArgument(keyFlag)
		if err := box.LoadKeyFile(path, password); err != nil {
			return nil, err
		}
	}

	for _, p := range certFlags {
		if err := box.AddCertFile(p); err != nil {
			return nil, err
		}
	}

	if caPath != "" {
		if err := box.LoadCABundleFile(caPath); err != nil {
			return nil, err
		}
	}

	if role != "" {
		if err := box.SelectKeyByRole(role); err != nil {
			return nil, err
		}
	}
	return box, nil
}

// mustRead reads all bytes from path, or from stdin if path is "" or "-".
func mustRead(path string) []byte {
	if path == "" || path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatalf("read stdin: %v", err)
		}
		return data
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	return data
}

// mustWrite writes data to path, or to stdout if path is "" or "-".
func mustWrite(path string, data []byte) {
	if path == "" || path == "-" {
		if _, err := os.Stdout.Write(data); err != nil {
			fatalf("write stdout: %v", err)
		}
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

// fatalf prints an error to stderr and exits with code 1.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "dstu: "+format+"\n", args...)
	os.Exit(1)
}

func splitKeyArgument(value string) (string, string) {
	start := 0
	if len(value) >= 3 && value[1] == ':' && (value[2] == '/' || value[2] == '\\') {
		start = 2
	}
	if offset := strings.IndexByte(value[start:], ':'); offset >= 0 {
		index := start + offset
		return value[:index], value[index+1:]
	}
	return value, ""
}
