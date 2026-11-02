//go:build integration

package ua

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/testiit"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/stretchr/testify/require"
)

// This opt-in test never reads a taxpayer keystore or report. Both the message
// and signing identity are disposable synthetic material. Only their imprints
// are sent to PrivatBank's TSA; no DPS submission occurs.
func TestLivePrivatPublicTimestampProfile(t *testing.T) {
	if os.Getenv("PRIVAT_PUBLIC_TSP_TEST") != "1" {
		t.Skip("set PRIVAT_PUBLIC_TSP_TEST=1 and public CA bundle paths")
	}
	rootBundle, err := os.ReadFile(os.Getenv("PRIVAT_PUBLIC_TSA_ROOT_BUNDLE"))
	require.NoError(t, err)
	rootCerts, err := cert.ParseCertificates(rootBundle)
	require.NoError(t, err)
	var roots [][]byte
	for _, root := range rootCerts {
		require.Equal(t, root.Subject.FullBytes, root.Issuer.FullBytes)
		roots = append(roots, root.Raw)
	}
	caBundle, err := os.ReadFile(os.Getenv("PRIVAT_PUBLIC_CA_BUNDLE"))
	require.NoError(t, err)
	discovery, err := cert.ParseCertificates(caBundle)
	require.NoError(t, err)
	key, err := dstu4145.GenerateKey(dstu4145.ParamsByName("DSTU_PB_257").Curve)
	require.NoError(t, err)
	signer := testiit.Certificate(t, key, false)
	box := NewBox()
	box.keys = []*keyEntry{{privateKey: key, signCert: signer}}
	box.certificates = discovery
	box.AddTSP("http://acsk.privatbank.ua/services/tsp/")
	content := []byte("Public interoperability test only; no taxpayer data or operational keys.")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	encoded, err := box.SignDocumentWithContext(ctx, content, SignOptions{NoTax: true, Timestamp: &TimestampSignOptions{TSARoots: roots, IncludeContentTimestamp: true}})
	require.NoError(t, err)
	message, err := cms.ParseSigned(encoded)
	require.NoError(t, err)
	contentTokens, err := message.ContentTimestampTokens(0)
	require.NoError(t, err)
	require.Len(t, contentTokens, 1)
	signatureTokens, err := message.SignatureTimestampTokens(0)
	require.NoError(t, err)
	require.Len(t, signatureTokens, 1)
	signature, err := message.SignatureBytes(0)
	require.NoError(t, err)
	verified, err := tsp.VerifySignatureTimestamp(signatureTokens[0], signature, rootCerts, time.Now(), discovery...)
	require.NoError(t, err)
	t.Logf("Public content/signature timestamps authenticated; signature timestamp time=%s", verified.Info.GenTime.Format(time.RFC3339))
	certificates := [][]byte{signer.Raw}
	certificates = append(certificates, roots...)
	request := testiit.Request{Operation: "verify", Data: content, Signature: encoded, Certificates: certificates, RequireTimestamp: true}
	result := testiit.Invoke(t, request)
	require.True(t, result.OK, result.Error)
	require.Equal(t, content, result.Data)
}
