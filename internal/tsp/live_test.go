//go:build integration

package tsp_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
	"crypto-dstu/internal/oid"
	"crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

func TestLivePublicTimestamp(t *testing.T) {
	if os.Getenv("TSP_LIVE") != "1" {
		t.Skip("set explicit public TSA endpoint and trust roots")
	}
	endpoint := os.Getenv("TSP_PUBLIC_URL")
	require.NotEmpty(t, endpoint)
	var roots []*cert.Certificate
	for _, path := range strings.Split(os.Getenv("TSP_PUBLIC_ROOTS"), ";") {
		require.NotEmpty(t, path)
		der, err := os.ReadFile(path)
		require.NoError(t, err)
		c, err := cert.ParseCertificate(der)
		require.NoError(t, err)
		roots = append(roots, c)
	}
	imprint, err := tsp.HashData([]byte("crypto-dstu public timestamp interoperability test"), oid.GOST34311)
	require.NoError(t, err)
	request, err := tsp.NewRequest(imprint, oid.GOST34311)
	require.NoError(t, err)
	der, err := request.Marshal()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	response, err := tsp.NewClient(endpoint).SendContext(ctx, der)
	require.NoError(t, err)
	token, err := response.Token()
	require.NoError(t, err)
	if output := os.Getenv("TSP_PUBLIC_CAPTURE"); output != "" {
		require.NoError(t, os.MkdirAll(output, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(output, "request.der"), der, 0600))
		require.NoError(t, os.WriteFile(filepath.Join(output, "token.der"), token, 0600))
	}
	info, err := tsp.ParseTSTInfo(token)
	require.NoError(t, err)
	t.Logf("genTime=%s imprint=%s", info.GenTime.UTC().Format(time.RFC3339Nano), info.MessageImprint.HashAlgorithm.Algorithm)
	message, err := cms.ParseSigned(token)
	require.NoError(t, err)
	for _, c := range message.Certificates {
		t.Logf("embedded certificate: %s signature=%s", c.CommonName, c.SigAlgOID)
	}
	verified, err := tsp.VerifyResponse(response, request, roots, time.Now())
	require.NoError(t, err)
	t.Logf("verified TSA=%s chain length=%d", verified.TSA.CommonName, len(verified.Chain))
}
