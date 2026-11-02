//go:build integration

package ocsp_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/ocsp"
	"github.com/stretchr/testify/require"
)

type captureOCSPTransport struct {
	base              http.RoundTripper
	request, response []byte
}

func (c *captureOCSPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.GetBody != nil {
		body, err := request.GetBody()
		if err != nil {
			return nil, err
		}
		c.request, err = io.ReadAll(body)
		body.Close()
		if err != nil {
			return nil, err
		}
	}
	response, err := c.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	c.response, err = io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(c.response))
	return response, nil
}

func TestLivePublicOCSP(t *testing.T) {
	if os.Getenv("OCSP_LIVE") != "1" {
		t.Skip("set OCSP_LIVE=1 and explicit public subject, issuer and endpoint")
	}
	read := func(name string) *cert.Certificate {
		t.Helper()
		path := os.Getenv(name)
		require.NotEmpty(t, path, name)
		der, err := os.ReadFile(path)
		require.NoError(t, err)
		c, err := cert.ParseCertificate(der)
		require.NoError(t, err)
		return c
	}
	subject, issuer := read("OCSP_PUBLIC_SUBJECT"), read("OCSP_PUBLIC_ISSUER")
	endpoint := os.Getenv("OCSP_PUBLIC_URL")
	require.NotEmpty(t, endpoint)
	require.NoError(t, cert.VerifyCert(subject, issuer))
	transport := &captureOCSPTransport{base: http.DefaultTransport}
	client := &ocsp.Client{URL: endpoint, HTTP: &http.Client{Timeout: 15 * time.Second, Transport: transport}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	response, err := client.CheckContext(ctx, subject, issuer)
	if output := os.Getenv("OCSP_PUBLIC_CAPTURE"); output != "" {
		require.NoError(t, os.MkdirAll(output, 0700))
		if transport.request != nil {
			require.NoError(t, os.WriteFile(filepath.Join(output, "request.der"), transport.request, 0600))
		}
		if transport.response != nil {
			require.NoError(t, os.WriteFile(filepath.Join(output, "response.der"), transport.response, 0600))
		}
	}
	require.NoError(t, err)
	t.Logf("subject %s; endpoint %s; outer status %d; produced %s", subject.CommonName, endpoint, response.Status, response.ProducedAt.UTC().Format(time.RFC3339))
	var crls [][]byte
	if path := os.Getenv("OCSP_PUBLIC_RESPONDER_CRL"); path != "" {
		der, err := os.ReadFile(path)
		require.NoError(t, err)
		crls = append(crls, der)
	}
	status, err := response.CheckWithPolicy(subject, issuer, ocsp.ValidationPolicy{Time: time.Now(), MaxAge: 24 * time.Hour, ClockSkew: 5 * time.Minute, ResponderCRLs: crls})
	require.NoError(t, err)
	require.Equal(t, ocsp.Good, status)
}
