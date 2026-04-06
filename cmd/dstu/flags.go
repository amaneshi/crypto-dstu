package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"crypto-dstu/ua"
)

// multiFlag implements flag.Value for flags that may be repeated (e.g. -cert, -tsp).
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
		parts := strings.SplitN(keyFlag, ":", 2)
		path := parts[0]
		password := ""
		if len(parts) == 2 {
			password = parts[1]
		}
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

	_ = role // role-based selection is handled per-command via box.KeyByRole
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
func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "dstu: "+format+"\n", args...)
	os.Exit(1)
}
