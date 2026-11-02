//go:build integration

package ocsp_test

import (
	"bytes"
	"compress/gzip"
	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/ocsp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These fixed-time checks exercise independently generated public wire artifacts.
// Their archived timestamps do not establish current certificate status.
func TestCapturedCZOOCSP(t *testing.T) {
	for _, year := range []string{"2021", "2025"} {
		t.Run(year, func(t *testing.T) {
			directory := filepath.Join("testdata", "czo-"+year)
			manifestDER, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
			require.NoError(t, err)
			var manifest struct {
				ValidatedAt time.Time
				Files       map[string]struct {
					SHA256 string
					Bytes  int
				}
			}
			require.NoError(t, json.Unmarshal(manifestDER, &manifest))
			read := func(name string) []byte {
				t.Helper()
				der, err := os.ReadFile(filepath.Join(directory, name))
				require.NoError(t, err)
				sum := sha256.Sum256(der)
				require.Equal(t, manifest.Files[name].SHA256, hex.EncodeToString(sum[:]))
				require.Len(t, der, manifest.Files[name].Bytes)
				return der
			}
			parse := func(name string) *cert.Certificate {
				t.Helper()
				c, err := cert.ParseCertificate(read(name))
				require.NoError(t, err)
				return c
			}
			subject, issuer := parse("subject.cer"), parse("issuer.cer")
			require.NoError(t, cert.VerifyCertAt(subject, issuer, manifest.ValidatedAt))
			response, err := ocsp.ParseResponse(read("response.der"))
			require.NoError(t, err)
			compressed, err := gzip.NewReader(bytes.NewReader(read("responder.crl.gz")))
			require.NoError(t, err)
			crl, err := io.ReadAll(io.LimitReader(compressed, (16<<20)+1))
			require.NoError(t, err)
			require.NoError(t, compressed.Close())
			require.LessOrEqual(t, len(crl), 16<<20)
			policy := ocsp.ValidationPolicy{Time: manifest.ValidatedAt, MaxAge: 24 * time.Hour, ClockSkew: 5 * time.Minute}
			_, err = response.CheckWithPolicy(subject, issuer, policy)
			require.Error(t, err, "a signature alone must not exempt responder revocation")
			policy.ResponderCRLs = [][]byte{crl}
			status, err := response.CheckWithPolicy(subject, issuer, policy)
			require.NoError(t, err)
			require.Equal(t, ocsp.Good, status)
			// Retain and authenticate the exact request sent to the public endpoint.
			require.NotEmpty(t, read("request.der"))
		})
	}
}
