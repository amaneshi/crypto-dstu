// Package czo provides helpers for downloading and locating CZO test fixtures.
package czo

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const baseURL = "https://czo.gov.ua/download/test_sign"

// File describes one CZO test fixture.
type File struct {
	// URL is the full download URL.
	URL string
	// Dest is the path relative to the czo testdata root.
	Dest string
}

// Files is the canonical list of CZO test fixtures used by the test suite.
// Source: https://czo.gov.ua/testexamples (saved as docs/test-samples.htm).
// Only DSTU / DSTU-7564 algorithm families are included; RSA/ECDSA files are omitted.
var Files = []File{
	// ── CAdES / DSTU 4145 ── enveloped (attached) ──────────────────────────
	{baseURL + "/CAdES/DSTU/enveloped/CAdES-BES/test.txt.p7s", "cades/DSTU/enveloped/CAdES-BES/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU/enveloped/CAdES-T/test.txt.p7s", "cades/DSTU/enveloped/CAdES-T/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU/enveloped/CAdES-C/test.txt.p7s", "cades/DSTU/enveloped/CAdES-C/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU/enveloped/CAdES-X_Long/test.txt.p7s", "cades/DSTU/enveloped/CAdES-X_Long/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU/enveloped/CAdES-X_Long-Full/test.txt.p7s", "cades/DSTU/enveloped/CAdES-X_Long-Full/test.txt.p7s"},

	// ── CAdES / DSTU 4145 ── detached ──────────────────────────────────────
	{baseURL + "/CAdES/DSTU/detached/CAdES-BES/test.txt", "cades/DSTU/detached/CAdES-BES/test.txt"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-BES/test.txt.p7s", "cades/DSTU/detached/CAdES-BES/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-T/test.txt", "cades/DSTU/detached/CAdES-T/test.txt"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-T/test.txt.p7s", "cades/DSTU/detached/CAdES-T/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-C/test.txt", "cades/DSTU/detached/CAdES-C/test.txt"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-C/test.txt.p7s", "cades/DSTU/detached/CAdES-C/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-X_Long/test.txt", "cades/DSTU/detached/CAdES-X_Long/test.txt"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-X_Long/test.txt.p7s", "cades/DSTU/detached/CAdES-X_Long/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-X_Long-Full/test.txt", "cades/DSTU/detached/CAdES-X_Long-Full/test.txt"},
	{baseURL + "/CAdES/DSTU/detached/CAdES-X_Long-Full/test.txt.p7s", "cades/DSTU/detached/CAdES-X_Long-Full/test.txt.p7s"},

	// ── CAdES / DSTU-7564 (Kupyna) ── enveloped ────────────────────────────
	{baseURL + "/CAdES/DSTU-7564/enveloped/CAdES-BES/test.txt.p7s", "cades/DSTU-7564/enveloped/CAdES-BES/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU-7564/enveloped/CAdES-T/test.txt.p7s", "cades/DSTU-7564/enveloped/CAdES-T/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU-7564/enveloped/CAdES-C/test.txt.p7s", "cades/DSTU-7564/enveloped/CAdES-C/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU-7564/enveloped/CAdES-X_Long/test.txt.p7s", "cades/DSTU-7564/enveloped/CAdES-X_Long/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU-7564/enveloped/CAdES-X_Long-Full/test.txt.p7s", "cades/DSTU-7564/enveloped/CAdES-X_Long-Full/test.txt.p7s"},

	// ── CAdES / DSTU-7564 ── detached ──────────────────────────────────────
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-BES/test.txt", "cades/DSTU-7564/detached/CAdES-BES/test.txt"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-BES/test.txt.p7s", "cades/DSTU-7564/detached/CAdES-BES/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-T/test.txt", "cades/DSTU-7564/detached/CAdES-T/test.txt"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-T/test.txt.p7s", "cades/DSTU-7564/detached/CAdES-T/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-C/test.txt", "cades/DSTU-7564/detached/CAdES-C/test.txt"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-C/test.txt.p7s", "cades/DSTU-7564/detached/CAdES-C/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-X_Long/test.txt", "cades/DSTU-7564/detached/CAdES-X_Long/test.txt"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-X_Long/test.txt.p7s", "cades/DSTU-7564/detached/CAdES-X_Long/test.txt.p7s"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-X_Long-Full/test.txt", "cades/DSTU-7564/detached/CAdES-X_Long-Full/test.txt"},
	{baseURL + "/CAdES/DSTU-7564/detached/CAdES-X_Long-Full/test.txt.p7s", "cades/DSTU-7564/detached/CAdES-X_Long-Full/test.txt.p7s"},

	// ── XAdES / DSTU ── enveloped + detached ───────────────────────────────
	{baseURL + "/XAdES/DSTU/enveloped/XAdES-B-B/test.xml", "xades/DSTU/enveloped/XAdES-B-B/test.xml"},
	{baseURL + "/XAdES/DSTU/enveloped/XAdES-B-T/test.xml", "xades/DSTU/enveloped/XAdES-B-T/test.xml"},
	{baseURL + "/XAdES/DSTU/enveloped/XAdES-B-LT/test.xml", "xades/DSTU/enveloped/XAdES-B-LT/test.xml"},
	{baseURL + "/XAdES/DSTU/enveloped/XAdES-B-LTA/test.xml", "xades/DSTU/enveloped/XAdES-B-LTA/test.xml"},
	{baseURL + "/XAdES/DSTU/detached/XAdES-B-B/test.xml", "xades/DSTU/detached/XAdES-B-B/test.xml"},
	{baseURL + "/XAdES/DSTU/detached/XAdES-B-B/sign.xml", "xades/DSTU/detached/XAdES-B-B/sign.xml"},
	{baseURL + "/XAdES/DSTU/detached/XAdES-B-T/test.xml", "xades/DSTU/detached/XAdES-B-T/test.xml"},
	{baseURL + "/XAdES/DSTU/detached/XAdES-B-T/sign.xml", "xades/DSTU/detached/XAdES-B-T/sign.xml"},
	{baseURL + "/XAdES/DSTU/detached/XAdES-B-LT/test.xml", "xades/DSTU/detached/XAdES-B-LT/test.xml"},
	{baseURL + "/XAdES/DSTU/detached/XAdES-B-LT/sign.xml", "xades/DSTU/detached/XAdES-B-LT/sign.xml"},
	{baseURL + "/XAdES/DSTU/detached/XAdES-B-LTA/test.xml", "xades/DSTU/detached/XAdES-B-LTA/test.xml"},
	{baseURL + "/XAdES/DSTU/detached/XAdES-B-LTA/sign.xml", "xades/DSTU/detached/XAdES-B-LTA/sign.xml"},

	// ── XAdES / DSTU-7564 ── enveloped + detached ──────────────────────────
	{baseURL + "/XAdES/DSTU-7564/enveloped/XAdES-B-B/test.xml", "xades/DSTU-7564/enveloped/XAdES-B-B/test.xml"},
	{baseURL + "/XAdES/DSTU-7564/enveloped/XAdES-B-T/test.xml", "xades/DSTU-7564/enveloped/XAdES-B-T/test.xml"},
	{baseURL + "/XAdES/DSTU-7564/enveloped/XAdES-B-LT/test.xml", "xades/DSTU-7564/enveloped/XAdES-B-LT/test.xml"},
	{baseURL + "/XAdES/DSTU-7564/enveloped/XAdES-B-LTA/test.xml", "xades/DSTU-7564/enveloped/XAdES-B-LTA/test.xml"},
	{baseURL + "/XAdES/DSTU-7564/detached/XAdES-B-B/test.xml", "xades/DSTU-7564/detached/XAdES-B-B/test.xml"},
	{baseURL + "/XAdES/DSTU-7564/detached/XAdES-B-B/sign.xml", "xades/DSTU-7564/detached/XAdES-B-B/sign.xml"},
	{baseURL + "/XAdES/DSTU-7564/detached/XAdES-B-T/test.xml", "xades/DSTU-7564/detached/XAdES-B-T/test.xml"},
	{baseURL + "/XAdES/DSTU-7564/detached/XAdES-B-T/sign.xml", "xades/DSTU-7564/detached/XAdES-B-T/sign.xml"},
	{baseURL + "/XAdES/DSTU-7564/detached/XAdES-B-LT/test.xml", "xades/DSTU-7564/detached/XAdES-B-LT/test.xml"},
	{baseURL + "/XAdES/DSTU-7564/detached/XAdES-B-LT/sign.xml", "xades/DSTU-7564/detached/XAdES-B-LT/sign.xml"},
	{baseURL + "/XAdES/DSTU-7564/detached/XAdES-B-LTA/test.xml", "xades/DSTU-7564/detached/XAdES-B-LTA/test.xml"},
	{baseURL + "/XAdES/DSTU-7564/detached/XAdES-B-LTA/sign.xml", "xades/DSTU-7564/detached/XAdES-B-LTA/sign.xml"},

	// ── PAdES / DSTU ───────────────────────────────────────────────────────
	{baseURL + "/PAdES/DSTU/PAdES-B-B/Test.pdf", "pades/DSTU/PAdES-B-B/Test.pdf"},
	{baseURL + "/PAdES/DSTU/PAdES-B-T/Test.pdf", "pades/DSTU/PAdES-B-T/Test.pdf"},
	{baseURL + "/PAdES/DSTU/PAdES-B-LT/Test.pdf", "pades/DSTU/PAdES-B-LT/Test.pdf"},
	{baseURL + "/PAdES/DSTU/PAdES-B-LTA/Test.pdf", "pades/DSTU/PAdES-B-LTA/Test.pdf"},

	// ── PAdES / DSTU-7564 ─────────────────────────────────────────────────
	{baseURL + "/PAdES/DSTU-7564/PAdES-B-B/Test.pdf", "pades/DSTU-7564/PAdES-B-B/Test.pdf"},
	{baseURL + "/PAdES/DSTU-7564/PAdES-B-T/Test.pdf", "pades/DSTU-7564/PAdES-B-T/Test.pdf"},
	{baseURL + "/PAdES/DSTU-7564/PAdES-B-LT/Test.pdf", "pades/DSTU-7564/PAdES-B-LT/Test.pdf"},
	{baseURL + "/PAdES/DSTU-7564/PAdES-B-LTA/Test.pdf", "pades/DSTU-7564/PAdES-B-LTA/Test.pdf"},

	// ── ASiC-S / DSTU ──────────────────────────────────────────────────────
	{baseURL + "/ASiC-S/DSTU/CAdES-BES/test.txt.asics", "asics/DSTU/CAdES-BES/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU/CAdES-T/test.txt.asics", "asics/DSTU/CAdES-T/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU/CAdES-C/test.txt.asics", "asics/DSTU/CAdES-C/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU/CAdES-X_Long/test.txt.asics", "asics/DSTU/CAdES-X_Long/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU/CAdES-X_Long-Full/test.txt.asics", "asics/DSTU/CAdES-X_Long-Full/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU/XAdES-B-B/test.txt.asics", "asics/DSTU/XAdES-B-B/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU/XAdES-B-T/test.txt.asics", "asics/DSTU/XAdES-B-T/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU/XAdES-B-LT/test.txt.asics", "asics/DSTU/XAdES-B-LT/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU/XAdES-B-LTA/test.txt.asics", "asics/DSTU/XAdES-B-LTA/test.txt.asics"},

	// ── ASiC-S / DSTU-7564 ────────────────────────────────────────────────
	{baseURL + "/ASiC-S/DSTU-7564/CAdES-BES/test.txt.asics", "asics/DSTU-7564/CAdES-BES/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU-7564/CAdES-T/test.txt.asics", "asics/DSTU-7564/CAdES-T/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU-7564/CAdES-C/test.txt.asics", "asics/DSTU-7564/CAdES-C/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU-7564/CAdES-X_Long/test.txt.asics", "asics/DSTU-7564/CAdES-X_Long/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU-7564/CAdES-X_Long-Full/test.txt.asics", "asics/DSTU-7564/CAdES-X_Long-Full/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU-7564/XAdES-B-B/test.txt.asics", "asics/DSTU-7564/XAdES-B-B/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU-7564/XAdES-B-T/test.txt.asics", "asics/DSTU-7564/XAdES-B-T/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU-7564/XAdES-B-LT/test.txt.asics", "asics/DSTU-7564/XAdES-B-LT/test.txt.asics"},
	{baseURL + "/ASiC-S/DSTU-7564/XAdES-B-LTA/test.txt.asics", "asics/DSTU-7564/XAdES-B-LTA/test.txt.asics"},

	// ── ASiC-E / DSTU ─────────────────────────────────────────────────────
	{baseURL + "/ASiC-E/DSTU/XAdES-B-B/test.txt.asice", "asice/DSTU/XAdES-B-B/test.txt.asice"},
	{baseURL + "/ASiC-E/DSTU/XAdES-B-T/test.txt.asice", "asice/DSTU/XAdES-B-T/test.txt.asice"},
	{baseURL + "/ASiC-E/DSTU/XAdES-B-LT/test.txt.asice", "asice/DSTU/XAdES-B-LT/test.txt.asice"},
	{baseURL + "/ASiC-E/DSTU/XAdES-B-LTA/test.txt.asice", "asice/DSTU/XAdES-B-LTA/test.txt.asice"},

	// ── Certificates ──────────────────────────────────────────────────────
	// CAdES certs (canonical; reused by czo_test.go czoCerts() helper)
	{baseURL + "/CAdES/DSTU/DSTU_sign.cer", "certs/DSTU/DSTU_sign.cer"},
	{baseURL + "/CAdES/DSTU/DSTU_encryption.cer", "certs/DSTU/DSTU_encryption.cer"},
	{baseURL + "/CAdES/DSTU-7564/DSTU_sign.cer", "certs/DSTU-7564/DSTU_sign.cer"},
	{baseURL + "/CAdES/DSTU-7564/DSTU_encryption.cer", "certs/DSTU-7564/DSTU_encryption.cer"},
	// XAdES certs
	{baseURL + "/XAdES/DSTU/DSTU_sign.cer", "certs/xades/DSTU/DSTU_sign.cer"},
	{baseURL + "/XAdES/DSTU/DSTU_encryption.cer", "certs/xades/DSTU/DSTU_encryption.cer"},
	{baseURL + "/XAdES/DSTU-7564/DSTU_sign.cer", "certs/xades/DSTU-7564/DSTU_sign.cer"},
	{baseURL + "/XAdES/DSTU-7564/DSTU_encryption.cer", "certs/xades/DSTU-7564/DSTU_encryption.cer"},
	// PAdES certs
	{baseURL + "/PAdES/DSTU/DSTU_sign.cer", "certs/pades/DSTU/DSTU_sign.cer"},
	{baseURL + "/PAdES/DSTU/DSTU_encryption.cer", "certs/pades/DSTU/DSTU_encryption.cer"},
	{baseURL + "/PAdES/DSTU-7564/DSTU_sign.cer", "certs/pades/DSTU-7564/DSTU_sign.cer"},
	{baseURL + "/PAdES/DSTU-7564/DSTU_encryption.cer", "certs/pades/DSTU-7564/DSTU_encryption.cer"},
	// ASiC-S certs
	{baseURL + "/ASiC-S/DSTU/DSTU_sign.cer", "certs/asics/DSTU/DSTU_sign.cer"},
	{baseURL + "/ASiC-S/DSTU/DSTU_encryption.cer", "certs/asics/DSTU/DSTU_encryption.cer"},
	{baseURL + "/ASiC-S/DSTU-7564/DSTU_sign.cer", "certs/asics/DSTU-7564/DSTU_sign.cer"},
	{baseURL + "/ASiC-S/DSTU-7564/DSTU_encryption.cer", "certs/asics/DSTU-7564/DSTU_encryption.cer"},
	// ASiC-E certs
	{baseURL + "/ASiC-E/DSTU/DSTU_sign.cer", "certs/asice/DSTU/DSTU_sign.cer"},
	{baseURL + "/ASiC-E/DSTU/DSTU_encryption.cer", "certs/asice/DSTU/DSTU_encryption.cer"},
}

// Root returns the absolute path to the testdata/czo directory.
func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// EnsureFiles downloads all fixtures that are not already on disk.
// It is safe to call concurrently from multiple TestMain functions.
func EnsureFiles() error {
	root := Root()
	client := &http.Client{Timeout: 30 * time.Second}

	for _, f := range Files {
		dest := filepath.Join(root, filepath.FromSlash(f.Dest))
		if _, err := os.Stat(dest); err == nil {
			continue // already present
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("czo: mkdir %s: %w", filepath.Dir(dest), err)
		}
		if err := download(client, f.URL, dest); err != nil {
			return fmt.Errorf("czo: download %s: %w", f.URL, err)
		}
	}
	return nil
}

func download(client *http.Client, url, dest string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// Path returns the absolute path for a fixture by its Dest key.
func Path(dest string) string {
	return filepath.Join(Root(), filepath.FromSlash(dest))
}
