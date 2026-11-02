package tsp

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	contentTypeRequest = "application/timestamp-query"
	contentTypeReply   = "application/timestamp-reply"
)

// Client is an HTTP client for communicating with a TSP server.
type Client struct {
	URL  string
	HTTP *http.Client
}

// NewClient creates a Client using the default HTTP transport.
func NewClient(url string) *Client {
	return &Client{
		URL:  url,
		HTTP: nil,
	}
}

// Timestamp sends a TSP request for the given pre-computed hash
// and returns an untrusted parsed response. The original nonce is not returned;
// use NewRequest, SendContext and VerifyResponse for authenticated requests.
func (c *Client) Timestamp(hash []byte, hashAlgOID asn1.ObjectIdentifier) (*Response, error) {
	req, err := NewRequest(hash, hashAlgOID)
	if err != nil {
		return nil, err
	}
	reqDER, err := req.Marshal()
	if err != nil {
		return nil, errors.New("tsp: marshal request: " + err.Error())
	}
	return c.Send(reqDER)
}

// Send transmits a pre-encoded TSP request DER and returns the parsed response.
func (c *Client) Send(reqDER []byte) (*Response, error) {
	return c.SendContext(context.Background(), reqDER)
}

// SendContext fetches bounded, untrusted timestamp evidence. VerifyImprint must
// authenticate it with the original request imprint and nonce before use.
func (c *Client) SendContext(ctx context.Context, reqDER []byte) (*Response, error) {
	if ctx == nil {
		return nil, errors.New("tsp: request context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(c.URL)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("tsp: invalid server URL")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("tsp: redirect rejected") }}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, errors.New("tsp: build HTTP request: " + err.Error())
	}
	httpReq.Header.Set("Content-Type", contentTypeRequest)

	httpResp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("tsp: HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, errors.New("tsp: HTTP status " + httpResp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, (4<<20)+1))
	if err != nil {
		return nil, errors.New("tsp: read response body: " + err.Error())
	}

	if len(body) > 4<<20 {
		return nil, errors.New("tsp: response exceeds size limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ParseResponse(body)
}
