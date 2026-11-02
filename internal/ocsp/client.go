package ocsp

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

	"github.com/amaneshi/crypto-dstu/internal/cert"
)

// Client performs OCSP requests over HTTP.
type Client struct {
	// HTTP is the underlying HTTP client. Nil means http.DefaultClient.
	HTTP *http.Client
	// URL overrides the OCSP URL. If empty, AIA from the certificate is used.
	URL string
}

// Check fetches and parses the OCSP status for cert issued by issuer.
// The OCSP URL is taken from c.URL if set, otherwise from the certificate's AIA extension.
func (c *Client) Check(subject, issuer *cert.Certificate) (*Response, error) {
	return c.CheckContext(context.Background(), subject, issuer)
}

// CheckContext fetches and parses evidence. Call Response.Check before using
// its certificate status; an HTTP success does not authenticate that status.
func (c *Client) CheckContext(ctx context.Context, subject, issuer *cert.Certificate) (*Response, error) {
	if ctx == nil {
		return nil, errors.New("ocsp: request context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if subject == nil || issuer == nil {
		return nil, errors.New("ocsp: Check: nil certificate")
	}

	cid, err := NewCertID(subject, issuer, asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26})
	if err != nil {
		return nil, err
	}

	req, err := NewRequest([]*CertID{cid})
	if err != nil {
		return nil, errors.New("ocsp: Check: " + err.Error())
	}
	der, err := req.Marshal()
	if err != nil {
		return nil, errors.New("ocsp: Check: marshal request: " + err.Error())
	}

	// Determine URL.
	endpoint := c.URL
	if endpoint == "" {
		urls := AIAOCSPURLs(subject)
		if len(urls) == 0 {
			return nil, errors.New("ocsp: Check: no OCSP URL in certificate AIA and none configured")
		}
		endpoint = urls[0]
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("ocsp: invalid responder URL")
	}

	// Post request.
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("ocsp: responder redirect rejected") }}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(der))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")
	httpResp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ocsp: Check: HTTP post: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()
	if httpResp.StatusCode != http.StatusOK {
		return nil, errors.New("ocsp: responder returned an HTTP error")
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, (4<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("ocsp: Check: read response: %w", err)
	}
	if len(body) > 4<<20 {
		return nil, errors.New("ocsp: response exceeds size limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return ParseResponse(body)
}

// AIAOCSPURLs extracts OCSP responder URLs from the certificate's
// Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1).
func AIAOCSPURLs(c *cert.Certificate) []string {
	return extractAIAOCSPURLs(c)
}

// oidAccessMethodOCSP is the accessMethod OID for OCSP in AIA (RFC 5280).
var oidAccessMethodOCSP = oidFromInts(1, 3, 6, 1, 5, 5, 7, 48, 1)

// oidAuthorityInfoAccess is the AIA extension OID.
var oidAuthorityInfoAccess = oidFromInts(1, 3, 6, 1, 5, 5, 7, 1, 1)

// Hash algorithm OIDs for CertID (mirrors oid package but avoids import cycle).
var (
	oidKupyna256 = oidFromInts(1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1)
	oidGOST34311 = oidFromInts(1, 2, 804, 2, 1, 1, 1, 1, 2, 1)
)

func oidFromInts(arcs ...int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier(arcs)
}

// extractAIAOCSPURLs parses the AIA extension of a certificate and returns all OCSP URLs.
func extractAIAOCSPURLs(c *cert.Certificate) []string {
	if c == nil {
		return nil
	}
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidAuthorityInfoAccess) {
			continue
		}
		return parseAIAOCSPURLs(ext.Value)
	}
	return nil
}

// parseAIAOCSPURLs decodes an AIA extension value and returns OCSP URLs.
// AIA ::= SEQUENCE OF AccessDescription
// AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
// GeneralName uniformResourceIdentifier is [6] IMPLICIT IA5String.
func parseAIAOCSPURLs(der []byte) []string {
	type accessDesc struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue
	}

	// Unwrap outer SEQUENCE.
	var wrapper asn1.RawValue
	rest, err := asn1.Unmarshal(der, &wrapper)
	if err != nil || len(rest) != 0 || wrapper.Tag != asn1.TagSequence {
		return nil
	}

	var urls []string
	inner := wrapper.Bytes
	for len(inner) > 0 {
		var ad accessDesc
		inner, err = asn1.Unmarshal(inner, &ad)
		if err != nil {
			break
		}
		if ad.Method.Equal(oidAccessMethodOCSP) && ad.Location.Class == 2 && ad.Location.Tag == 6 && !ad.Location.IsCompound {
			urls = append(urls, string(ad.Location.Bytes))
		}
	}
	return urls
}
