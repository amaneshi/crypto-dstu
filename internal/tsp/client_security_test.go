package tsp_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTimestampHTTPBoundsAndCancellation(t *testing.T) {
	called := false
	client := &tsp.Client{URL: "https://example.invalid/tsp", HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		require.Equal(t, "application/timestamp-query", r.Header.Get("Content-Type"))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(make([]byte, (4<<20)+1))), Header: make(http.Header)}, nil
	})}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.SendContext(ctx, []byte{0x30, 0})
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, called)
	_, err = client.SendContext(context.Background(), []byte{0x30, 0})
	require.ErrorContains(t, err, "exceeds size limit")
	require.True(t, called)
	_, err = client.SendContext(nil, []byte{0x30, 0})
	require.Error(t, err)
	client.URL = "file:///tmp/tsp"
	_, err = client.SendContext(context.Background(), nil)
	require.Error(t, err)
}
