package tsp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"encoding/asn1"
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
		HTTP: &http.Client{},
	}
}

// Timestamp hashes and sends a TSP request for the given pre-computed hash
// and returns the parsed response.
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
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.URL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, errors.New("tsp: build HTTP request: " + err.Error())
	}
	httpReq.Header.Set("Content-Type", contentTypeRequest)

	httpResp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, errors.New("tsp: HTTP request: " + err.Error())
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, errors.New("tsp: HTTP status " + httpResp.Status)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, errors.New("tsp: read response body: " + err.Error())
	}

	return ParseResponse(body)
}
